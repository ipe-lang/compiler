use super::{
    BuildOptions, CliError, EmittedCrate, FlooredBuild, NativeFinish, OutTarget, SourceGraph,
    analysis_graphs, analysis_root, analysis_target, attribute_canon_errors,
    attribute_post_link_error, build_project_into, build_test_into,
    capabilities_including_served_widgets, classify_entry_shape, create_source_root,
    discover_manifest, emit_machine_error, emitted_bin_filename, entry_modules, frame_infer_error,
    home_to_source_map, lowering_check_query, program_constructs_a_widget, resolve_runtime,
    resolve_vendored_runtime_dir, run_build, runtime_context_for_message, typecheck_target,
    working_dir,
};
use crate::cargo_step::{CargoOutput, CargoTarget, Verbosity};
use crate::output_dir::{EmitTarget, OutputArea, OutputRoot, OwnedDir, ProjectPaths};
use crate::project_root::{AnalysisTarget, FileArg, ProjectRoot, SourceDir};
use crate::publisher::{AttestedActor, BlessedPublisher};
use crate::remote_ingest::{InheritedError, InheritedInput, InheritedRole, run_inherited};
use crate::source_snapshot::{Limits, SourceOrigin, SourceSnapshot, TestView};
use crate::verb::Verb;
use crate::{
    Applicability, BTreeMap, Diagnostic, HelpLine, Interner, Path, PathBuf, Suggestion, Write,
    audit, cli_args, delivery, ffi, fmt, fs, index, pack, progress, project, publish, resolve,
    scratch, style, text, toolchain, version_check,
};
use zeroize::Zeroizing;

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
    /// The bundle profile a native build finished in `finish` packages: a
    /// release bundle only behind the release consent witness.
    pub(crate) const fn of(finish: &NativeFinish<'_>) -> Self {
        match finish {
            NativeFinish::Dev => Self::Dev,
            NativeFinish::Release { .. } => Self::Release,
        }
    }

    /// The build intent the bundle's crate is emitted with.
    ///
    /// The `release` bundle is a shipped artifact, so it is a release build;
    /// the `build` bundle is a development build, like every `build` verb.
    pub const fn build_intent(self) -> ipe_backend_rust::BuildIntent {
        match self {
            Self::Dev => ipe_backend_rust::BuildIntent::Development,
            Self::Release => ipe_backend_rust::BuildIntent::Release,
        }
    }

    /// The emitted crate's area under the output root.
    ///
    /// `rust/` for [`Self::Dev`], `release/rust/` for [`Self::Release`] — where
    /// `build` and `release` respectively put it.
    const fn crate_areas(self) -> &'static [OutputArea] {
        match self {
            Self::Dev => &[OutputArea::Rust],
            Self::Release => &[OutputArea::Release, OutputArea::Rust],
        }
    }

    /// Claim the directory this profile's packaged bundles go in.
    ///
    /// `dist/` for [`Self::Dev`], `release/dist/` for [`Self::Release`].
    fn dist_dir(self, output: &OutputRoot) -> Result<OwnedDir, CliError> {
        let areas: &[OutputArea] = match self {
            Self::Dev => &[OutputArea::Dist],
            Self::Release => &[OutputArea::Release, OutputArea::Dist],
        };
        output.claim_area(areas)
    }

    /// The compiled binary's `target/` profile subdirectory (`debug` / `release`),
    /// matching the cargo profile [`FlooredBuild`] picks for the same posture.
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
    /// [`CliError::Usage`] if the mobile OS resolution refuses (unreachable
    /// through the typed [`delivery::Host`]).
    pub fn from_delivery_host(host: delivery::Host) -> Result<Option<Self>, CliError> {
        let mobile = |word| {
            pack::mobile::resolve_os(Some(word))
                .map(Self::Mobile)
                .map_err(|r| CliError::Usage(crate::text::Message::relay(&r)))
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
/// as [`CliError::Usage`] when the app's shape/target does not fit the host;
/// the underlying build's errors; [`CliError::Io`] on any filesystem failure.
pub fn bundle_delivery(
    host: BundleHost,
    finish: NativeFinish<'_>,
    path: Option<&str>,
) -> Result<(), CliError> {
    match host {
        BundleHost::Desktop => pack_desktop(finish, path),
        BundleHost::Mobile(os) => pack_mobile(os, BundleProfile::of(&finish), path),
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
        None => Ok(desktop_app_shape(classify_entry_shape(root)?)),
    }
}

/// The desktop app shape a classified `main` shape packages as.
pub const fn desktop_app_shape(shape: delivery::Shape) -> pack::desktop::AppShape {
    match shape {
        delivery::Shape::Web => pack::desktop::AppShape::WebView,
        delivery::Shape::Tui | delivery::Shape::Cli => pack::desktop::AppShape::Terminal,
        // A `script` renders nothing and a `worker` runs a view-less loop (a
        // server is a `script` running `Server.listen`, rendering http rather
        // than a desktop window); all classify as a plain program so the
        // webview gate refuses them by name.
        delivery::Shape::Script | delivery::Shape::Worker => pack::desktop::AppShape::Program,
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
/// [`CliError::Usage`] wrapping [`pack::desktop::DesktopRefusal`] when the
/// shape is not webview-capable.
pub fn validate_desktop_shape(
    declared: Option<project::EntryShape>,
    root: &Path,
) -> Result<(), CliError> {
    let shape = classify_desktop_shape(declared, root)?;
    pack::desktop::require_webview(shape)
        .map_err(|r| CliError::Usage(crate::text::Message::relay(&r)))
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
/// [`CliError::Usage`] wrapping [`pack::mobile::MobileRefusal`] when the
/// shape is not a wasm-enabled `Web` app.
pub fn validate_mobile_shape(
    declared: Option<project::EntryShape>,
    root: &Path,
    wasm: &project::WasmConfig,
) -> Result<(), CliError> {
    let cap = classify_mobile_spa_cap(declared, root, wasm)?;
    pack::mobile::require_web_spa(cap).map_err(|r| CliError::Usage(crate::text::Message::relay(&r)))
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
/// It carries the webview proof the gate minted, so the packaged app is always
/// emitted for the webview host.
pub struct GatedDesktop<'a> {
    assembler: BundleAssembler<'a>,
    finish: NativeFinish<'a>,
    webview: delivery::WebViewProof,
}

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
        self.assembler
            .assemble_desktop(os, self.finish, self.webview)
    }

    /// Emit the packaged app's crate into `out` without running cargo.
    ///
    /// # Errors
    /// Build/emit errors from the underlying compile.
    #[cfg(test)]
    pub fn emit(&self, out: OutTarget<'_>) -> Result<EmittedCrate, CliError> {
        self.assembler.emit_desktop(out, self.webview)
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
    /// [`CliError::Usage`] wrapping a [`pack::desktop::DesktopRefusal`] when
    /// the shape is not webview-capable; classification errors from the entry
    /// source when no shape is declared.
    pub fn gate_desktop(
        manifest: &'a project::ProjectManifest,
        manifest_path: &'a Path,
        finish: NativeFinish<'a>,
        root: &Path,
    ) -> Result<GatedDesktop<'a>, CliError> {
        validate_desktop_shape(manifest.default_program().and_then(|p| p.shape), root)?;
        // The desktop packager ships the `web desktop` delivery, so the gate
        // that admitted the shape mints its webview proof.
        let delivery::HostIntent::WebView(webview) =
            delivery::Delivery::web_desktop().host_intent()
        else {
            // `web desktop` always resolves to the webview host; were it not
            // to, the packager refuses rather than bundle a served program.
            return Err(CliError::Usage(crate::text::Message::relay(
                &pack::desktop::DesktopRefusal::NotWebView {
                    shape: pack::desktop::AppShape::Program.as_str(),
                },
            )));
        };
        Ok(GatedDesktop {
            assembler: Self::new(manifest, manifest_path, BundleProfile::of(&finish)),
            finish,
            webview,
        })
    }

    /// Run the mobile shape gate ([`validate_mobile_shape`]) and, only when it
    /// passes, mint a [`GatedMobile`] witness wrapping the assembler. This is the
    /// sole constructor of a runnable mobile assembler, so ungated mobile
    /// assembly is unrepresentable.
    ///
    /// # Errors
    /// [`CliError::Usage`] wrapping a [`pack::mobile::MobileRefusal`] when
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

    /// Emit the desktop app's crate into `out` for the webview host `webview`
    /// proves.
    ///
    /// # Errors
    /// Build/emit errors from the underlying compile.
    fn emit_desktop(
        &self,
        out: OutTarget<'_>,
        webview: delivery::WebViewProof,
    ) -> Result<EmittedCrate, CliError> {
        let runtime_dir = resolve_vendored_runtime_dir(None, false)?;
        build_project_into(
            self.manifest_path,
            out,
            &runtime_dir,
            &BuildOptions {
                intent: self.profile.build_intent(),
                ..BuildOptions::from_env()
            },
            delivery::HostIntent::WebView(webview),
        )
    }

    /// Emit + compile the app to a binary, generate the desktop bundle layout,
    /// and materialise (Linux) or describe (macOS/Windows) the bundle on disk.
    /// Private: reached only through a [`GatedDesktop`] witness, so the shape
    /// gate is already proven passed.
    ///
    /// # Errors
    /// Build/emit errors from the underlying compile; [`CliError::Io`] on any
    /// filesystem failure while materialising the bundle.
    fn assemble_desktop(
        &self,
        os: pack::desktop::DesktopOs,
        finish: NativeFinish<'_>,
        webview: delivery::WebViewProof,
    ) -> Result<(), CliError> {
        use std::fmt::Write as _;

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
        let output = OutputRoot::resolve(None, &ProjectPaths::from_manifest(manifest))?;
        let rust_target = EmitTarget::Area(output.area(&[OutputArea::Rust]));
        let crate_dir = self.emit_desktop(OutTarget::Proven(&rust_target), webview)?;

        let cargo_bin = toolchain::require_cargo(toolchain::ToolIntent::Build)?;
        // A `release web desktop` bundle carries an optimised binary and its
        // consented floor; the `build` dev bundle carries a plain debug one and
        // the development marker.
        let target_dir = crate::target_dir::LinkableTargetDir::for_crate(
            cargo_bin.path(),
            crate_dir.path(),
            None,
        )?;
        FlooredBuild {
            cargo: &cargo_bin,
            crate_dir: &crate_dir,
            finish,
            target: CargoTarget::Host,
            target_dir: &target_dir,
            output: CargoOutput::Human(Verbosity::Progress),
            what: "the desktop app",
            runtime: None,
        }
        .run()?;

        // Read the compiled binary back from the build directory the build was
        // handed, then materialise (Linux) or describe (macOS/Windows).
        let bin_name = emitted_bin_filename(crate_dir.path())?;
        let binary = target_dir
            .path()
            .join(self.profile.target_subdir())
            .join(&bin_name);
        if !binary.is_file() {
            return Err(CliError::Usage(text::msg::app_binary_missing(
                &binary.display(),
            )));
        }

        let dist = self.profile.dist_dir(&output)?.child(os.as_str())?;
        let bundle_root = pack::desktop::materialise(&layout, &binary, icon, &dist)?;

        let mut body = format!(
            "packaged `{}` for {} → {}\n  {}\n",
            manifest.name,
            os.as_str(),
            bundle_root.display(),
            os.webview_runtime_note()
        );
        if os != pack::desktop::DesktopOs::Linux {
            let _ = writeln!(
                body,
                "  note: the {} bundle layout is written here, but a signed, runnable {} \
                 artifact must be produced on a {} runner (unsigned; cross-tooling out of scope).",
                os.as_str(),
                os.as_str(),
                os.as_str()
            );
        }
        crate::screen::Screen::new(crate::screen::Stream::Stdout)
            .line(crate::screen::Tone::Text, &body)
            .emit();
        Ok(())
    }

    /// Build the wasm SPA, collect its `www/` tree, generate the mobile shell
    /// layout, and materialise the shell on disk. Private: reached only through
    /// a [`GatedMobile`] witness, so the shape gate is already proven passed.
    ///
    /// The shell is laid out for the manifest's mount base, the one the wasm
    /// build bakes into the bundle's URLs; a base that changes while the build
    /// runs is refused before any shell is written.
    ///
    /// # Errors
    /// The wasm build's own errors; [`CliError::Usage`] wrapping
    /// [`pack::mobile::MobileRefusal::ManifestChanged`] when the manifest's mount
    /// base changed during the build; [`CliError::Io`] on any filesystem failure
    /// while collecting the bundle or materialising the shell.
    fn assemble_mobile(&self, os: pack::mobile::MobileOs) -> Result<(), CliError> {
        let manifest = self.manifest;
        let base = &manifest.delivery.browser.base;
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

        // Build the `--target wasm` SPA into the project's output root, then
        // collect its `www/` tree from the profile's crate. The wasm bundle
        // pipeline (emit + cargo + wasm-bindgen) is the single source of the
        // hostable bundle; invoking it through this binary keeps that pipeline
        // authoritative rather than re-implemented here.
        let output = OutputRoot::resolve(None, &ProjectPaths::from_manifest(manifest))?;
        build_under_fixed_base(self.manifest_path, base, || {
            build_wasm_for_mobile(self.manifest_path, output.path(), self.profile)
        })?;
        // The SPA is read from the owned crate; a symlinked `www/` is refused so
        // the shell can never pick up files from outside the build output.
        let www_dir = output
            .claim_area(self.profile.crate_areas())?
            .path_to("www")?
            .path();
        let bundle = pack::mobile::SpaBundle::from_www_dir(&www_dir)
            .map_err(|e| CliError::Usage(crate::text::Message::relay(&e)))?;

        let layout =
            pack::mobile::layout(os, self.profile, &identity, accepts, &bundle, icon, base)?;

        let dist = self.profile.dist_dir(&output)?.child(os.as_str())?;
        let shell_root = pack::mobile::materialise(&layout, icon, &dist)?;

        let note = if os.build_runs_on_linux() {
            crate::text::mobile_android_note()
        } else {
            crate::text::mobile_ios_note()
        };
        crate::screen::Screen::new(crate::screen::Stream::Stdout)
            .line(
                crate::screen::Tone::Text,
                &format!(
                    "packaged `{}` for {} → {}\n  {note}",
                    manifest.name,
                    os.as_str(),
                    shell_root.display()
                ),
            )
            .emit();
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
/// [`CliError::Usage`] wrapping a [`pack::desktop::DesktopRefusal`];
/// build/emit errors from the underlying compile; [`CliError::Io`] on any
/// filesystem failure while materialising the bundle.
pub fn pack_desktop(finish: NativeFinish<'_>, path: Option<&str>) -> Result<(), CliError> {
    // The desktop bundle is the host OS's webview-native app; the delivery
    // grammar carries no per-OS override (a cross-OS artifact is finished on that
    // OS's own runner), so the packager always targets this host's OS.
    let os = pack::desktop::resolve_os(None)
        .map_err(|r| CliError::Usage(crate::text::Message::relay(&r)))?;

    let root = path.map_or_else(|| PathBuf::from("."), PathBuf::from);
    let manifest_path =
        discover_manifest(&root)?.ok_or(CliError::Usage(text::msg::pkg_not_found_in_dir()))?;
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
    BundleAssembler::gate_desktop(&manifest, &manifest_path, finish, &root)?.assemble(os)
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
/// [`CliError::Usage`] wrapping a [`pack::mobile::MobileRefusal`]; the wasm
/// build's own errors; [`CliError::Io`] on any filesystem failure while
/// collecting the bundle or materialising the shell.
pub fn pack_mobile(
    os: pack::mobile::MobileOs,
    profile: BundleProfile,
    path: Option<&str>,
) -> Result<(), CliError> {
    let root = path.map_or_else(|| PathBuf::from("."), PathBuf::from);
    let manifest_path =
        discover_manifest(&root)?.ok_or(CliError::Usage(text::msg::pkg_not_found_in_dir()))?;
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

/// Build the hostable SPA bundle under `output_root` through this binary.
///
/// `ipe dev build --target wasm` for a dev bundle (`<root>/rust/www/`), `ipe
/// release build --target wasm` for a production one (`<root>/release/rust/www/`).
///
/// Invoking the same binary keeps the wasm bundle pipeline (emit + cargo +
/// wasm-bindgen) authoritative — the mobile shell hosts exactly the bundle a
/// plain wasm build/release produces, never a re-implemented variant. The profile
/// carries through so a `release web solo <os>` shell hosts the production SPA.
///
/// # Errors
/// [`CliError::Usage`] when this binary's path cannot be resolved or the
/// wasm build exits non-zero; [`CliError::Io`] when the build cannot be spawned
/// or waited on.
pub fn build_wasm_for_mobile(
    manifest_path: &Path,
    output_root: &Path,
    profile: BundleProfile,
) -> Result<(), CliError> {
    let exe = std::env::current_exe()
        .map_err(|e| CliError::Usage(text::msg::wasm_ipe_binary_unknown(&e)))?;
    let project_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let mut build = std::process::Command::new(&exe);
    build
        .args(wasm_build_verb(profile).argv())
        .arg(project_dir)
        .args(["--target", "wasm", "--out"])
        .arg(output_root);
    let status =
        run_inherited(build, InheritedRole::SelfBuild, InheritedInput::Terminal).map_err(|e| {
            CliError::Io {
                path: exe,
                source: e.into(),
            }
        })?;
    if !status.success() {
        return Err(CliError::Usage(text::msg::mobile_wasm_build_failed(
            &status.code().unwrap_or(1),
        )));
    }
    Ok(())
}

/// Run `build`, then re-read the manifest at `manifest_path` and refuse when its
/// mount base is no longer `planned`: the bundle the build produced and the shell
/// laid out for `planned` must name one mount path.
///
/// # Errors
/// `build`'s own error; the manifest re-read's error; [`CliError::Usage`]
/// wrapping [`pack::mobile::MobileRefusal::ManifestChanged`] when the base
/// differs.
fn build_under_fixed_base(
    manifest_path: &Path,
    planned: &ipe_runtime_rust::encoding::MountBase,
    build: impl FnOnce() -> Result<(), CliError>,
) -> Result<(), CliError> {
    build()?;
    let after = project::parse_manifest(manifest_path)?
        .delivery
        .browser
        .base;
    if after == *planned {
        return Ok(());
    }
    Err(CliError::Usage(text::Message::relay(
        &pack::mobile::MobileRefusal::ManifestChanged {
            before: planned.clone(),
            after,
        },
    )))
}

/// The verb a mobile shell's wasm bundle is built with.
///
/// A dev shell hosts a `dev build --target wasm` bundle; a release shell hosts
/// a production `release build --target wasm` bundle (Debug.* gated,
/// optimised).
#[must_use]
pub const fn wasm_build_verb(profile: BundleProfile) -> Verb {
    match profile {
        BundleProfile::Dev => Verb::DEV_BUILD,
        BundleProfile::Release => Verb::RELEASE_BUILD,
    }
}

/// `release build --emit-permissions <ios|macos|android> [<path>]` — the
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
/// [`CliError::Usage`] on a platform word outside the closed
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
        .map_err(|e| CliError::Usage(text::msg::emit_permissions_failed(&verb, &e)))?;

    let root = path.map_or_else(|| PathBuf::from("."), PathBuf::from);
    let manifest_path =
        discover_manifest(&root)?.ok_or(CliError::Usage(text::msg::pkg_not_found_in_dir()))?;

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
    crate::screen::Screen::new(crate::screen::Stream::Stdout)
        .line(crate::screen::Tone::Text, &out)
        .emit();
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
/// [`CliError::Usage`] on a missing or unknown subcommand; the subcommand's
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
        None => Err(CliError::Usage(text::msg::package_usage())),
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
/// [`CliError::Usage`] when no entry file is given; [`CliError::Usage`] on a
/// bad path or an extra argument; the parser's [`CliError::Resolve`] /
/// [`CliError::Io`] when the entry is malformed or unreadable.
pub fn run_validate_entry(rest: &[String]) -> Result<(), CliError> {
    let path = match rest {
        [one] => PathBuf::from(one),
        [] => {
            return Err(CliError::Usage(text::msg::package_validate_entry_usage()));
        }
        _ => {
            return Err(CliError::Usage(
                text::msg::package_validate_entry_single_path(),
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
    crate::screen::Screen::new(crate::screen::Stream::Stdout)
        .line(crate::screen::Tone::Text, &body)
        .emit();
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
/// [`CliError::Usage`] when no entry file is given; [`CliError::Usage`] on
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
    let index_root = index_root_opt
        .clone()
        .map_or_else(resolve::index_root, Ok)?;
    let baseline: Option<index::IndexEntry> =
        index::read_entry_lookup(&index_root, submitted.name.as_str()).require_present()?;

    // Structural prechecks (no fetch): version-count ceiling, per-version
    // immutability against the baseline, and source continuity (anti-squat). This
    // is the authoritative wall (ADR 0007) — it enforces these even for an entry
    // hand-edited around the author-side `ipe publish`, which an attacker opening
    // the index PR directly would bypass.
    index::admission_precheck(&submitted, baseline.as_ref(), attested_actor.as_ref())?;

    let baseline_by_version: std::collections::BTreeMap<
        &crate::published_version::PublishedVersion,
        &index::EntryVersion,
    > = baseline
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
        return Err(CliError::Usage(text::msg::audit_entry_nothing_new(
            &submitted.name,
        )));
    }

    // Steps 3 and 4 for every new version, in a private scratch directory under
    // the standard per-user cache root (the write-boundary from PRINCIPLES.md).
    let passing = certify_versions(
        &resolve::default_cache_base()?,
        &submitted.name,
        &new_versions,
        &crate::remote_ingest::PACKAGE_SOURCE,
        |checkout, version| {
            // Step 4 — audit: run the full Tier-1 (+ Tier-2 where applicable) gate on
            // the verified source tree. Pass --index so the enforced-semver check reads
            // the right baseline. Reject on the first failing check.
            audit_version(
                checkout,
                version,
                &submitted,
                index_root_opt.as_deref(),
                blessing.as_ref(),
            )
        },
    )?;

    // All new versions passed — print the certified summary.
    let versions_list = passing.join(", ");
    let body = format!(
        "audit-entry: {} — {} new version(s) certified: {versions_list}",
        submitted.name,
        passing.len()
    );
    crate::screen::Screen::new(crate::screen::Stream::Stdout)
        .line(crate::screen::Tone::Text, &body)
        .emit();
    Ok(())
}

/// Fetch, hash-verify and `audit` each of `versions` of `name`, held to `budget`,
/// in one private scratch directory under `cache_base`; returns the certified
/// versions.
///
/// The directory is unpredictably named, created exclusively with owner-only
/// access, and removed on every return — a fetch refusal, a hash mismatch or an
/// audit rejection leaves nothing under `cache_base`.
///
/// # Errors
/// [`CliError::Io`] when the scratch directory cannot be created; the first
/// fetch, verify or `audit` error otherwise.
pub fn certify_versions(
    cache_base: &Path,
    name: &crate::package_name::PackageName,
    versions: &[&index::EntryVersion],
    budget: &crate::remote_ingest::FetchBudget,
    mut audit: impl FnMut(&Path, &index::EntryVersion) -> Result<(), CliError>,
) -> Result<Vec<String>, CliError> {
    let parent = cache_base.join("ipe");
    let scratch =
        scratch::ScratchDir::new_under(&parent, "audit-entry").map_err(|source| CliError::Io {
            path: parent,
            source,
        })?;
    versions
        .iter()
        .map(|version| {
            // Step 3 — fetch + verify: git-fetch the source at the pinned revision
            // and assert the fetched tree's sha256 equals the index pin. A
            // mismatch is a CliError::HashMismatch — the fetched bytes are not the
            // source the publisher registered, so nothing derived from them is
            // trusted.
            let checkout = resolve::fetch_and_verify_index_version_within(
                scratch.path(),
                name,
                version,
                budget,
            )?;
            audit(&checkout, version)?;
            Ok(version.version.to_string())
        })
        .collect()
}

/// Run the full package audit on the verified `checkout` of `version` of the
/// `submitted` entry.
///
/// # Errors
/// The typed [`CliError`] of the first failing check.
fn audit_version(
    checkout: &Path,
    version: &index::EntryVersion,
    submitted: &index::IndexEntry,
    index_root: Option<&Path>,
    blessing: Result<&BlessedPublisher, &crate::publisher::BlessingRefusal>,
) -> Result<(), CliError> {
    // Audit the checkout path itself, never an argv round-trip of it: a lossy
    // string of a non-UTF-8 path names another directory. The submitted entry's
    // claimed publisher is named in a reject, and the attestation-backed
    // blessing exempts only a proven blessed publisher from the
    // reserved-namespace ownership check — the admission-time squat-proofing of
    // the trusted namespace.
    let options = audit::AuditOptions::for_admission(
        submitted.publisher.clone(),
        index_root.map(Path::to_path_buf),
    );
    // Typed errors propagate directly: the audit's `CliError` names the failing
    // check, and the chatter below names the version.
    audit::capture_package(checkout)
        .and_then(|snapshot| audit::run_audit_over(snapshot, &options, blessing))
        .and_then(|audited| admit_against_audit(version, submitted.name.as_str(), &audited))
        .inspect_err(|_| {
            crate::screen::chatter(
                crate::screen::Stream::Stderr,
                crate::screen::Tone::UserError,
                &format!(
                    "audit-entry: `{}` version {} rejected",
                    submitted.name, version.version
                ),
            );
        })
}

/// Admit a submitted entry `version` only when it records what the audit of its source certified.
///
/// The entry's `sha256` must be the digest of the tree the audit judged, and
/// its `capabilities` the set the audit inferred: the index records the
/// audit's own output, never a submitted claim beside it.
///
/// # Errors
/// [`CliError::HashMismatch`] when the recorded digest is not the audited one;
/// [`CliError::PackageAudit`] when the recorded capabilities are not the audited set.
pub fn admit_against_audit(
    version: &index::EntryVersion,
    package: &str,
    audited: &audit::AuditedPackage,
) -> Result<(), CliError> {
    if version.sha256 != *audited.digest() {
        return Err(CliError::HashMismatch {
            package: package.to_owned(),
            expected: version.sha256.as_str().to_owned(),
            actual: audited.digest().as_str().to_owned(),
        });
    }
    audited.refuse_other_capabilities(&version.capabilities)
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
/// [`CliError::Usage`] when the entry file is missing; [`CliError::Usage`] on
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
                let value = it.next().ok_or_else(|| {
                    CliError::Usage(text::msg::flag_needs_value(
                        &"package audit-entry",
                        &"--attested-actor",
                    ))
                })?;
                if attested_actor.is_some() {
                    return Err(CliError::Usage(text::msg::flag_repeated(
                        &"package audit-entry",
                        &"--attested-actor",
                    )));
                }
                attested_actor = Some(AttestedActor::parse(value)?);
            }
            "--index" => {
                let value = it.next().ok_or_else(|| {
                    CliError::Usage(text::msg::flag_needs_value(
                        &"package audit-entry",
                        &"--index",
                    ))
                })?;
                if index_root.is_some() {
                    return Err(CliError::Usage(text::msg::flag_repeated(
                        &"package audit-entry",
                        &"--index",
                    )));
                }
                index_root = Some(PathBuf::from(value));
            }
            flag if flag.starts_with('-') => {
                return Err(cli_args::usage_unknown_flag("package audit-entry", flag));
            }
            positional => {
                if entry_path.is_some() {
                    return Err(CliError::Usage(text::msg::package_audit_entry_single_path()));
                }
                entry_path = Some(PathBuf::from(positional));
            }
        }
    }
    let entry_path = entry_path.ok_or(CliError::Usage(text::msg::package_audit_entry_usage()))?;
    Ok(AuditEntryArgs {
        entry_path,
        index_root,
        attested_actor,
    })
}

/// `ipe type-check [<path>]` — type-check a program and stop. Runs the same
/// injection-aware source graph `ipe dev build` uses, but demands only the
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
    run_type_check_in(&working_dir()?, rest)
}

/// [`run_type_check_body`] with `cwd` as the current directory.
///
/// # Errors
/// Every refusal of [`analysis_root`], [`analysis_target`] and
/// [`typecheck_target`].
pub fn run_type_check_in(cwd: &Path, rest: &[String]) -> Result<(), CliError> {
    let args = cli_args::parse_type_check(rest)?;
    // Propagate any diagnostic raw; `run_type_check` routes it through the
    // resolved output format (the single machine-error boundary).
    typecheck_in(cwd, args.entry.as_deref())?;
    match args.format {
        cli_args::OutputFormat::Json => {
            // The shared machine envelope; a clean type-check carries an empty
            // payload (the outcome is the `status`, there is no result data).
            let payload = cli_args::json::object(&[]);
            crate::screen::emit_machine(
                crate::screen::Stream::Stdout,
                &crate::machine_output::MachineOutput::ok(
                    "ipe.cli.type-check/1",
                    "type-check",
                    payload,
                )
                .render_json(),
            );
        }
        cli_args::OutputFormat::Plain => {
            crate::screen::emit_machine(crate::screen::Stream::Stdout, "ok\n");
        }
        cli_args::OutputFormat::Human => {
            let p = style::Palette::for_stream(&std::io::stdout());
            let (glyph, tint) = style::Outcome::Success.glyph_and_tint(p);
            crate::screen::Screen::new(crate::screen::Stream::Stdout)
                .styled(&format!(
                    "{tint}{glyph} {}{}",
                    text::type_check_ok(),
                    p.reset,
                ))
                .emit();
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

/// Stage 3: the build — the same compilation as `ipe dev build`.
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
/// The test entry is the module `tests/Main.ipe` of the project `path` names:
/// a project directory, its `package.ipe`, or a module under its `src/` or
/// `tests/`; with no `path`, the current directory. The project is resolved
/// exactly as `ipe dev build` resolves it ([`ProjectRoot::resolve`]): the
/// directory must hold `package.ipe` itself, and no parent directory is ever
/// searched. The test program is the snapshot's own test universe
/// ([`SourceSnapshot::test_view`]) — the entry, the project's `src/` tree, its
/// other `tests/` modules, and the stdlib closure and FFI preparation over the
/// one catalog the snapshot read — built with the manifest's settings, so the
/// program under test is the program the project build ships. When the test
/// entry is absent the runner returns [`TestOutcome::NoTestEntry`] — a project
/// with no test entry is not an error. When it exists, the test runner is
/// compiled to a temporary output directory, the emitted Rust project is built
/// with `cargo build`, and the resulting `ipe-app` binary is executed. The
/// binary itself prints the per-test failures and the `N passed, M failed`
/// summary (from `Ipe.Test.runMain`) to stdout; this function only classifies
/// its exit code.
///
/// # Errors
/// [`CliError::TestFailed`] when the test binary exits non-zero (one or more
/// cases failed) — the binary's own output is the report. Otherwise every
/// refusal of [`ProjectRoot::resolve`], [`ProjectRoot::target`],
/// [`SourceSnapshot::read`] and [`SourceSnapshot::test_view`], or any build or
/// toolchain error encountered while compiling the runner.
pub fn run_project_tests(path: Option<&str>) -> Result<TestOutcome, CliError> {
    run_project_tests_with(&working_dir()?, path, TestStdio::Inherit)
}

/// The shared test runner over the project `path` names from `cwd`,
/// parameterised by where the test binary's own summary goes ([`TestStdio`]).
///
/// See [`run_project_tests`] for the resolution rules.
///
/// # Errors
/// As [`run_project_tests`].
pub fn run_project_tests_with(
    cwd: &Path,
    path: Option<&str>,
    stdio: TestStdio,
) -> Result<TestOutcome, CliError> {
    let (root, file) = analysis_root(cwd, path.map(Path::new))?;
    // A named file selects its project and nothing more; it must still lie
    // under the project's `src/` or `tests/`.
    analysis_target(&root, file.as_ref())?;
    let snapshot = SourceSnapshot::read(&root, Limits::DEFAULT)?;
    let Some(entry) = snapshot.test_entry(&[TEST_ENTRY_MODULE.to_owned()]) else {
        return Ok(TestOutcome::NoTestEntry);
    };
    // The test universe is judged, its FFI calls included, before any
    // toolchain is asked for.
    let view = SourceSnapshot::test_view(entry)?;

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

    let outcome = build_and_run_test_entry(
        &TestProgram {
            root: &root,
            view: &view,
            host: crate::delivery::HostIntent::Served,
        },
        &out_scratch,
        &runtime_dir,
        &cargo_bin,
        stdio,
    );

    // `out_scratch` drops here, removing the temp directory on every exit path
    // (compile failure, cargo error, spawn error, or normal completion).
    drop(out_scratch);
    outcome
}

/// The module every project's test program is entered at: `tests/Main.ipe`.
const TEST_ENTRY_MODULE: &str = "Main";

/// One test program: the project it belongs to, its universe, and the host it is built for.
#[derive(Clone, Copy)]
pub struct TestProgram<'a> {
    /// The resolved project, the source of the build's settings.
    pub root: &'a ProjectRoot,
    /// The program's modules and FFI preparation.
    pub view: &'a TestView,
    /// The host the program is built for.
    pub host: crate::delivery::HostIntent,
}

/// Compile the test entry into `out_scratch`, build the emitted Rust project, and
/// run the resulting test binary, classifying its exit code.
///
/// Split from [`run_project_tests`] so the caller's temp-directory cleanup runs
/// on every exit of this fallible sequence, not only the success path.
///
/// The build directory is held locked from before the build until the built
/// binary is copied out ([`crate::target_dir::LinkableTargetDir::for_scratch`]),
/// pinned or shared alike. Under that lock the crate's `Cargo.lock` is seeded
/// from the directory's lock slot, every unit of the previous test runner is
/// cleaned (so the verdict never comes from a stale test unit), the crate is
/// built, its lock is stored back to the slot, and the binary is copied into a
/// private directory. The copy runs after the lock is released, so no later
/// build can replace the binary this run judges.
///
/// # Errors
/// The compile/build error on a compile or cargo failure; the refusals of
/// [`crate::target_dir::LinkableTargetDir::for_scratch`];
/// [`CliError::Io`] when the lock slot, the binary copy, or the spawn fails;
/// [`CliError::TestFailed`] when the binary exits non-zero (a failing case, or
/// a crash/signal with no exit code).
pub fn build_and_run_test_entry(
    program: &TestProgram<'_>,
    out_scratch: &scratch::ScratchDir,
    runtime_dir: &Path,
    cargo_bin: &crate::toolchain::CargoBin,
    stdio: TestStdio,
) -> Result<TestOutcome, CliError> {
    let crate_dir = build_test_into(
        program.root,
        program.view,
        program.host,
        OutTarget::Scratch(out_scratch),
        runtime_dir,
    )?;

    let target = crate::target_dir::LinkableTargetDir::for_scratch(cargo_bin.path(), out_scratch)?;
    seed_test_lock(target.dir().path(), crate_dir.dir())?;
    let build = FlooredBuild {
        cargo: cargo_bin,
        crate_dir: &crate_dir,
        finish: NativeFinish::Dev,
        target: CargoTarget::Host,
        target_dir: target.dir(),
        output: CargoOutput::Human(Verbosity::Progress),
        what: "the emitted test runner",
        runtime: runtime_context_for_message(),
    };
    build.clean_package(ipe_backend_rust::TEST_CRATE_NAME)?;
    build.run()?;
    store_test_lock(target.dir().path(), crate_dir.dir())?;

    // Read the compiled binary back from the build directory the build was
    // handed, so a `CARGO_TARGET_DIR` or `[build] target-dir` pin is the one
    // the build used.
    let test_bin_name = emitted_bin_filename(crate_dir.path())?;
    let compiled = target.dir().path().join("debug").join(&test_bin_name);
    let run_dir = scratch::ScratchDir::new_under(target.dir().path(), "ipe-test-run")
        .or_else(|_| scratch::ScratchDir::new("ipe-test-run"))
        .map_err(|source| CliError::ScratchUnavailable { source })?;
    let bin = run_dir.path().join(&test_bin_name);
    fs::copy(&compiled, &bin).map_err(|e| io_err(&compiled, e))?;
    drop(target.release());

    // Run the test binary. `Ipe.Test.runMain` exits 0 on all-pass, 1 on any
    // failure — propagate that as a stage error.
    let run_status = run_test_binary(bin, stdio, std::io::stderr);
    drop(run_dir);
    let run_status = run_status?;

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

/// The lock slot of a build directory: the test runner's last built `Cargo.lock`.
pub const TEST_LOCK_SLOT: &str = "ipe-test.Cargo.lock";

/// The most bytes a `Cargo.lock` carried through [`TEST_LOCK_SLOT`] may hold.
const TEST_LOCK_CAP: u64 = 16 * 1024 * 1024;

/// Seed `crate_dir`'s `Cargo.lock` from `target`'s [`TEST_LOCK_SLOT`], when that is a regular file.
///
/// The seeded lock is only a candidate: the build's offline `--locked` probe
/// still judges it, and a drifted one is resolved afresh.
///
/// # Errors
/// [`CliError::Io`] when the slot cannot be read or is larger than
/// [`TEST_LOCK_CAP`]; the refusals of writing the crate's lock.
fn seed_test_lock(target: &Path, crate_dir: &OwnedDir) -> Result<(), CliError> {
    match read_regular_entry(target, TEST_LOCK_SLOT)? {
        Some(lock) => crate_dir.path_to("Cargo.lock")?.write(&lock),
        None => Ok(()),
    }
}

/// Store `crate_dir`'s `Cargo.lock` as `target`'s [`TEST_LOCK_SLOT`].
///
/// The slot is replaced through an exclusively created temp file and a
/// rename, so it is never written through a link and never seen half written.
///
/// # Errors
/// [`CliError::Io`] when the crate's lock cannot be read or the slot cannot be written.
fn store_test_lock(target: &Path, crate_dir: &OwnedDir) -> Result<(), CliError> {
    let Some(lock) = read_regular_entry(crate_dir.path(), "Cargo.lock")? else {
        return Ok(());
    };
    let slot = target.join(TEST_LOCK_SLOT);
    let temp = target.join(format!(".{TEST_LOCK_SLOT}.{}.tmp", std::process::id()));
    match fs::remove_file(&temp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_err(&temp, e)),
    }
    let written = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .and_then(|mut file| file.write_all(&lock))
        .and_then(|()| fs::rename(&temp, &slot));
    written.map_err(|e| {
        let _ = fs::remove_file(&temp);
        io_err(&slot, e)
    })
}

/// The bytes of the regular file `name` in `dir`, read without following a link.
///
/// `None` when the entry is absent, a link, or not a regular file.
///
/// # Errors
/// [`CliError::Io`] when `dir` cannot be opened or the file cannot be read or
/// is larger than [`TEST_LOCK_CAP`].
fn read_regular_entry(dir: &Path, name: &str) -> Result<Option<Vec<u8>>, CliError> {
    let path = dir.join(name);
    let entry = ipe_fs_open::EntryName::new(std::ffi::OsStr::new(name))
        .ok_or_else(|| io_err(&path, std::io::ErrorKind::InvalidInput.into()))?;
    let cap = ipe_fs_open::ByteCap::new(TEST_LOCK_CAP)
        .ok_or_else(|| io_err(&path, std::io::ErrorKind::InvalidInput.into()))?;
    let opened = ipe_fs_open::HeldDir::open_root(dir).and_then(|held| held.open_regular(&entry));
    match opened {
        Ok(file) => file
            .read_bytes(cap)
            .map(Some)
            .map_err(|refusal| io_err(&path, refusal.into_io())),
        Err(
            ipe_fs_open::OpenRefusal::Absent
            | ipe_fs_open::OpenRefusal::Link
            | ipe_fs_open::OpenRefusal::NotRegular(_),
        ) => Ok(None),
        Err(refusal) => Err(io_err(&path, refusal.into_io())),
    }
}

/// Run the compiled test binary `bin` to its exit, its output placed as `stdio` says.
///
/// [`TestStdio::Inherit`] leaves the terminal's stdout and stderr in place.
/// [`TestStdio::Quiet`] points both of the binary's streams at `cli_stderr`
/// (the CLI's own stderr in production), so the CLI's stdout carries only its
/// machine verdict while the binary's summary and its own stderr still reach
/// the user. Nothing the binary writes passes through the CLI's memory.
///
/// # Errors
/// [`CliError::Io`] naming `bin` when the binary cannot be started or waited on.
fn run_test_binary<S: Into<std::process::Stdio>>(
    bin: PathBuf,
    stdio: TestStdio,
    cli_stderr: impl Fn() -> S,
) -> Result<std::process::ExitStatus, CliError> {
    let command = match stdio {
        TestStdio::Inherit => std::process::Command::new(&bin),
        TestStdio::Quiet => {
            let mut command = std::process::Command::new(&bin);
            command.stdout(cli_stderr()).stderr(cli_stderr());
            command
        }
    };
    let ran = run_inherited(
        command,
        InheritedRole::UserProgram,
        test_binary_stdin(stdio),
    );
    ran.map_err(|e| CliError::Io {
        path: bin,
        source: e.into(),
    })
}

/// What the compiled test binary reads on its stdin when its output is placed as `stdio` says.
///
/// An inherited run is the user's, at the terminal. A quiet run serves a
/// machine consumer of the CLI's stdout, so the binary reads the null device
/// rather than the stdin that consumer may still be writing to or holding open.
const fn test_binary_stdin(stdio: TestStdio) -> InheritedInput {
    match stdio {
        TestStdio::Inherit => InheritedInput::Terminal,
        TestStdio::Quiet => InheritedInput::Null,
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
/// [`CliError::Usage`] on an unexpected option or extra argument.
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
    match run_project_tests_with(&working_dir()?, path, TestStdio::Quiet) {
        Ok(TestOutcome::AllPassed) => {
            json_line(&verdict("passed"));
            Ok(())
        }
        Ok(TestOutcome::NoTestEntry) => {
            json_line(&verdict("no-tests"));
            Ok(())
        }
        Err(CliError::TestFailed { code }) => {
            json_line(&json::object(&[
                ("result", json::string("failed")),
                ("exitCode", code.to_string()),
            ]));
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
/// [`CliError::Usage`] on an unexpected option or extra argument. Otherwise
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
                report: crate::style::TerminalSafe::sanitize(&err.to_string()),
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
            json_line(&json::object(&[
                ("result", json::string("failed")),
                ("stage", json::string(name)),
            ]));
            return Err(CliError::DiagnosticJsonEmitted);
        }
    }
    json_line(&json::object(&[
        ("result", json::string("passed")),
        ("stages", stages.len().to_string()),
    ]));
    Ok(())
}

/// Write one machine JSON object to stdout as its own line.
fn json_line(object: &str) {
    crate::screen::emit_machine(crate::screen::Stream::Stdout, &format!("{object}\n"));
}

/// The type-check stage in machine-quiet form: the same source-graph type-check
/// as [`verify_check`], but through the non-printing core so stdout stays clean
/// for the JSON verdict (a diagnostic still renders through the error channel).
pub fn verify_check_quiet(path: Option<&str>) -> Result<(), CliError> {
    typecheck_in(&working_dir()?, path)
}

/// Type-check what `arg` names in the project at `cwd`: every entry when there is none.
///
/// # Errors
/// Every refusal of [`analysis_root`], [`analysis_target`] and
/// [`typecheck_target`].
pub fn typecheck_in(cwd: &Path, arg: Option<&str>) -> Result<(), CliError> {
    let (root, file) = analysis_root(cwd, arg.map(Path::new))?;
    typecheck_target(&analysis_target(&root, file.as_ref())?)
}

/// The test stage in machine-quiet form: the shared runner with the test
/// binary's own summary routed to stderr, so stdout stays the JSON verdict alone.
pub fn verify_test_quiet(path: Option<&str>) -> Result<(), CliError> {
    run_project_tests_with(&working_dir()?, path, TestStdio::Quiet).map(|_| ())
}

pub fn run_capabilities(rest: &[String]) -> Result<(), CliError> {
    let (format, positional) = cli_args::split_format(rest, "capabilities")?;
    let caps = capabilities_in(&working_dir()?, positional.first().copied())?;
    let names: Vec<&'static str> = caps.iter().map(|c| c.as_str()).collect();
    crate::screen::emit_report(
        format,
        &render_capabilities(&names, format, &std::io::stdout()),
    );
    Ok(())
}

/// The capabilities what `arg` names in the project at `cwd` exercises.
///
/// No argument (or a directory, or `package.ipe`) is every entry of the
/// project, their sets unioned. A file argument must name one of the
/// project's entries: a capability set is a program's, and any other module
/// is not one.
///
/// # Errors
/// Every refusal of [`analysis_root`] and [`analysis_target`];
/// [`CliError::Usage`] for a file naming no entry; [`CliError::Pipeline`] when
/// an entry does not lower.
pub fn capabilities_in(
    cwd: &Path,
    arg: Option<&str>,
) -> Result<std::collections::BTreeSet<ipe_ir::Capability>, CliError> {
    let (root, file) = analysis_root(cwd, arg.map(Path::new))?;
    let target = analysis_target(&root, file.as_ref())?;
    if let (Some(file), AnalysisTarget::Module { dir, module, .. }) = (file.as_ref(), &target) {
        let entries = entry_modules(root.entries());
        if *dir != SourceDir::Src || !entries.contains(&module.as_slice()) {
            let named: Vec<String> = entries
                .iter()
                .map(|entry| format!("src/{}.ipe", entry.join("/")))
                .collect();
            return Err(CliError::Usage(text::msg::capabilities_not_an_entry(
                &file.path().display(),
                &named.join(", "),
            )));
        }
    }
    target_capabilities(&target)
}

/// The union of the capabilities every entry `target` names exercises.
///
/// # Errors
/// [`CliError::Pipeline`] when an entry does not lower; every refusal of
/// [`analysis_graphs`].
fn target_capabilities(
    target: &AnalysisTarget<'_>,
) -> Result<std::collections::BTreeSet<ipe_ir::Capability>, CliError> {
    let mut caps = std::collections::BTreeSet::new();
    for graph in analysis_graphs(target)? {
        let program = graph.run_attributed(graph.entry_path(), |db, root, file| {
            ipe_db::lower_program(db, root, file).clone()
        })?;
        caps.extend(capabilities_including_served_widgets(
            &graph.db,
            graph.source_root,
            graph.entry_file,
            &program,
        ));
    }
    Ok(caps)
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
    let text = render_version(format, &std::io::stdout());
    match format {
        cli_args::OutputFormat::Human => {
            crate::screen::emit_banner(crate::screen::Stream::Stdout, &text);
        }
        cli_args::OutputFormat::Plain | cli_args::OutputFormat::Json => {
            crate::screen::emit_machine(crate::screen::Stream::Stdout, &text);
        }
    }
    Ok(())
}

/// The one-liner installer URL.
///
/// The same script the docs' `curl … | sh` install uses; `ipe upgrade` re-runs it
/// to fetch the latest release binary and install it over the current one. `pub`
/// so the install-drift test can assert the README `curl` one-liner and this
/// self-updater URL stay in agreement.
pub const INSTALL_SH_URL: &str =
    "https://raw.githubusercontent.com/ipe-lang/compiler/main/install.sh";

/// The env var marking an `install.sh` run launched by this wrapper.
///
/// A direct `curl | sh` never sets it. `pub` so the install-drift test can
/// assert `install.sh` reads the same name — see [`run_installer`].
pub const UPGRADE_WRAPPED_ENV: &str = "IPE_UPGRADE_WRAPPED";

/// The env var naming the private file a wrapped `install.sh` writes its
/// resolved release tag into when no prebuilt binary exists.
///
/// `pub` so the install-drift test can assert `install.sh` reads the same
/// name — see [`run_installer`].
pub const UPGRADE_TAG_FILE_ENV: &str = "IPE_UPGRADE_TAG_FILE";

/// Byte ceiling on the tag file `install.sh` hands back; a longer file is
/// refused, never parsed.
const UPGRADE_TAG_MAX_BYTES: usize = 128;

/// Parse the tag file's bytes into a normalised `vMAJOR.MINOR.PATCH[-pre][+build]`.
///
/// Accepts exactly one line (one trailing `\n` allowed) holding a `v`-prefixed
/// semver tag, optionally `ipe-`-prefixed — the shape of a release tag. Empty,
/// oversize, non-UTF-8, multi-line, whitespace-padded or non-semver input is
/// `None`, so no installer-written byte reaches the terminal unparsed.
fn parse_installer_tag(raw: &[u8]) -> Option<String> {
    if raw.len() > UPGRADE_TAG_MAX_BYTES {
        return None;
    }
    let text = std::str::from_utf8(raw).ok()?;
    let line = text.strip_suffix('\n').unwrap_or(text);
    let tag = line.strip_prefix("ipe-").unwrap_or(line);
    let version = semver::Version::parse(tag.strip_prefix('v')?).ok()?;
    Some(format!("v{version}"))
}

/// Read the tag `install.sh` wrote into `tag_file` back through the retained
/// handle (same inode, capped one byte past the ceiling so an oversize file is
/// detected rather than truncated into a plausible tag), then parse it.
fn read_installer_tag(tag_file: Option<&mut crate::scratch::ScratchFile>) -> Option<String> {
    use std::io::Read as _;
    let tag_file = tag_file?;
    tag_file.rewind().ok()?;
    let cap = u64::try_from(UPGRADE_TAG_MAX_BYTES.saturating_add(1)).ok()?;
    let mut raw = Vec::new();
    (&mut tag_file.file).take(cap).read_to_end(&mut raw).ok()?;
    parse_installer_tag(&raw)
}

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
/// [`CliError::Usage`] on an unknown flag or a non-POSIX host.
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
                    return Err(CliError::Usage(text::msg::plain_json_exclusive(&"upgrade")));
                }
                format = Some(cli_args::OutputFormat::Plain);
            }
            "--json" => {
                if format.is_some() {
                    return Err(CliError::Usage(text::msg::plain_json_exclusive(&"upgrade")));
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

    // --dry-run: show the installer command and stop — no version check needed.
    if dry_run {
        crate::screen::Screen::new(crate::screen::Stream::Stdout)
            .line(
                crate::screen::Tone::Text,
                &format!("would run: {}", installer_command()),
            )
            .emit();
        return Ok(());
    }

    let vc = version_check::version_check();
    let action = vc.action();

    // --plain / --json: emit machine output and never prompt or install.
    if fmt != cli_args::OutputFormat::Human {
        crate::screen::emit_machine(
            crate::screen::Stream::Stdout,
            &render_upgrade(&vc, &action, false, fmt),
        );
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
            crate::screen::Screen::new(crate::screen::Stream::Stdout)
                .styled(&format!(
                    "{tint}{glyph}{} {}",
                    p.reset,
                    text::upgrade_up_to_date(&v)
                ))
                .emit();
            if check && exit_code_flag {
                return Err(CliError::UpgradeCheckExit {
                    code: check_exit_code(&version_check::UpgradeAction::UpToDate),
                });
            }
            return Ok(());
        }
        version_check::UpgradeAction::Unreachable => {
            let (glyph, tint) = style::Outcome::Failure.glyph_and_tint(p);
            crate::screen::Screen::new(crate::screen::Stream::Stdout)
                .styled(&format!(
                    "{tint}{glyph}{}  {}",
                    p.reset,
                    text::upgrade_feed_unreachable()
                ))
                .emit();
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
            let (glyph, tint) = style::Outcome::Step.glyph_and_tint(p);
            crate::screen::Screen::new(crate::screen::Stream::Stdout)
                .styled(&format!(
                    "{tint}{glyph}{} {}",
                    p.reset,
                    text::upgrade_available(&cur, &lat)
                ))
                .emit();
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
        crate::screen::prompt(&format!("{}{} ", style::GUTTER, text::upgrade_confirm()));
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

    run_installer()
}

/// The installer hand-off `ipe upgrade` performs, as a shell command a user can run by hand.
fn installer_command() -> String {
    format!("curl -fsSL {INSTALL_SH_URL} | sh")
}

/// Download the installer script into a private file under [`remote_ingest::INSTALLER`].
///
/// The script is complete and within its ceilings before anything runs it, so
/// a stalled or oversized response is refused rather than half-executed.
///
/// # Errors
/// [`CliError::RemoteIngestExceeded`] past a ceiling; [`CliError::Usage`] when
/// curl cannot run or the download fails.
fn download_installer() -> Result<crate::scratch::ScratchFile, CliError> {
    use crate::remote_ingest::{self, Curl, RunError, Transfer};
    let budget = &remote_ingest::INSTALLER;
    let script =
        crate::scratch::ScratchFile::create("ipe-upgrade-installer").map_err(|e| CliError::Io {
            path: std::path::PathBuf::from("ipe-upgrade-installer"),
            source: e,
        })?;
    let output = Curl::https()
        .args(["--silent", "--show-error", "--fail", "--location"])
        .args(remote_ingest::curl_limit_args(
            remote_ingest::INSTALLER_MAX_BYTES,
            budget,
        ))
        .arg("-o")
        .arg(script.path())
        .arg(INSTALL_SH_URL)
        .run(None, Some(script.path()), &Transfer::begin(*budget))
        .map_err(|e| match e {
            RunError::Spawn(e) => CliError::Usage(text::msg::upgrade_installer_launch_failed(&e)),
            RunError::Wait(e) => CliError::Usage(text::msg::upgrade_installer_wait_failed(&e)),
            RunError::Measure(path, source) => CliError::Io { path, source },
            RunError::Exceeded(refusal) => CliError::RemoteIngestExceeded(refusal),
            RunError::PipeDrainTimeout(stream) => CliError::ChildPipeHeld(stream),
            RunError::PipeRead(stream, kind) => CliError::ChildPipeUnread(stream, kind),
        })?;
    if let Some(refusal) =
        remote_ingest::curl_refusal(output.status, remote_ingest::INSTALLER_MAX_BYTES, budget)
    {
        return Err(CliError::RemoteIngestExceeded(refusal));
    }
    if !output.status.success() {
        return Err(CliError::Usage(
            text::msg::upgrade_installer_download_failed(&output.stderr.to_terminal()),
        ));
    }
    Ok(script)
}

/// Read the downloaded installer `script` back, held to the download's byte ceiling.
///
/// The download measured the file against `INSTALLER_MAX_BYTES`; reading it
/// back under the same ceiling bounds the bytes held in memory at the read
/// itself, whatever the file holds by then.
///
/// # Errors
/// [`CliError::Io`] when the file cannot be rewound or read;
/// [`CliError::RemoteIngestExceeded`] when it holds more than the ceiling.
fn read_installer_script(
    mut script: crate::scratch::ScratchFile,
) -> Result<Zeroizing<Vec<u8>>, CliError> {
    use crate::remote_ingest::{self, CappedReadError};
    script.rewind().map_err(|source| CliError::Io {
        path: script.path().to_path_buf(),
        source,
    })?;
    remote_ingest::read_capped(
        &script.file,
        remote_ingest::INSTALLER_MAX_BYTES,
        remote_ingest::INSTALLER.source(),
    )
    .map(Zeroizing::new)
    .map_err(|e| match e {
        CappedReadError::Io(source) => CliError::Io {
            path: script.path().to_path_buf(),
            source,
        },
        CappedReadError::Exceeded(refusal) => CliError::RemoteIngestExceeded(refusal),
    })
}

/// Whether a host can run the release installer, a POSIX `sh` script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallerSupport {
    /// The host runs `sh` scripts.
    Supported,
    /// The host is not POSIX, so the installer is refused before any download.
    Unsupported,
}

/// This host's installer support: the installer runs on Unix alone.
const HOST_INSTALLER: InstallerSupport = if cfg!(unix) {
    InstallerSupport::Supported
} else {
    InstallerSupport::Unsupported
};

/// Refuse the installer where `support` says it cannot run.
///
/// # Errors
/// [`CliError::Usage`] naming the manual install command when `support` is
/// [`InstallerSupport::Unsupported`].
fn installer_gate(support: InstallerSupport) -> Result<(), CliError> {
    match support {
        InstallerSupport::Supported => Ok(()),
        InstallerSupport::Unsupported => Err(CliError::Usage(
            text::msg::upgrade_unsupported_platform(&installer_command()),
        )),
    }
}

/// Download the installer script, then run it and wait for it to finish.
///
/// The script is read back through the retained handle of the file it was
/// downloaded into, held to the download's own byte ceiling, and reaches `sh`
/// on its standard input exactly as a `curl | sh` pipe would, so the bytes run
/// are the bytes that were downloaded and measured. The installer
/// exits 2 when no prebuilt binary exists for the current platform; any other
/// non-zero exit is a generic failure.
///
/// # Errors
/// [`CliError::Usage`] when the host is not POSIX, the installer cannot be
/// downloaded or launched, or it exits with a non-zero code that is not 2;
/// [`CliError::RemoteIngestExceeded`] when the download crosses its ceilings;
/// [`CliError::UpgradeNoPrebuilt`] when the installer exits 2.
pub fn run_installer() -> Result<(), CliError> {
    installer_gate(HOST_INSTALLER)?;

    let download = progress::Stage::start(std::io::stderr(), "Downloading the release installer…");
    let script = match download_installer().and_then(read_installer_script) {
        Ok(script) => {
            download.success("Installer downloaded.");
            script
        }
        Err(e) => {
            download.failure("Could not download the installer.");
            return Err(e);
        }
    };

    // Render the hand-off to the installer as a stage on stderr, settled BEFORE
    // the child inherits the terminal, so the installer's own staged output
    // begins on a fresh, uncorrupted line. A launch that fails after the
    // hand-off is reported as the command's error.
    let stage = progress::Stage::start(std::io::stderr(), "Launching the release installer…");
    // IPE_UPGRADE_WRAPPED tells install.sh it is running under us: on its
    // "no prebuilt binary" failure it skips its own stderr banner (we render
    // the one failure message ourselves, below) and writes the tag it actually
    // resolved and probed into the private (0600, unpredictably named) file
    // named by IPE_UPGRADE_TAG_FILE, so we report the real target version
    // instead of guessing. The script arrives on stdin; stdout and stderr stay
    // inherited, untouched. Without a tag file install.sh keeps its own banner.
    let mut tag_file = crate::scratch::ScratchFile::create("ipe-upgrade-tag").ok();
    let mut installer = std::process::Command::new("sh");
    installer.arg("-s").env(UPGRADE_WRAPPED_ENV, "1");
    match &tag_file {
        Some(file) => installer.env(UPGRADE_TAG_FILE_ENV, file.path()),
        None => installer.env_remove(UPGRADE_TAG_FILE_ENV),
    };
    stage.success("Handing off to the installer — following its progress below.");
    let status = run_inherited(
        installer,
        InheritedRole::InteractiveInstall,
        InheritedInput::Bytes(script),
    )
    .map_err(|e| match e {
        InheritedError::Spawn(refusal) => {
            CliError::Usage(text::msg::upgrade_installer_launch_failed(&refusal))
        }
        InheritedError::Feed(kind) => {
            CliError::Usage(text::msg::upgrade_installer_short_feed(&kind))
        }
        InheritedError::Wait(e) => CliError::Usage(text::msg::upgrade_installer_wait_failed(&e)),
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
        // install.sh hands back the tag it actually resolved and probed (see
        // IPE_UPGRADE_TAG_FILE above); fall back to the running binary's
        // version only when that channel is absent or fails the strict parse.
        let version = read_installer_tag(tag_file.as_mut())
            .unwrap_or_else(|| format!("v{}", env!("CARGO_PKG_VERSION")));
        return Err(CliError::UpgradeNoPrebuilt {
            version: crate::style::TerminalSafe::sanitize(&version),
            platform: crate::style::TerminalSafe::sanitize(&platform),
        });
    }
    Err(CliError::Usage(text::msg::upgrade_installer_failed()))
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
/// - Human (default): the product header alone, a blank line before and after;
///   the version rides in the header.
/// - `--plain`: the bare version string, flush-left, nothing else.
/// - `--json`: the shared `{schema, status, command, payload}` machine envelope,
///   with the version under `payload.version` (`ipe.cli.version/1`).
pub fn render_version(format: cli_args::OutputFormat, stream: &impl std::io::IsTerminal) -> String {
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
        Human => style::command_header(style::use_color(stream)),
    }
}

/// Verify a declared capability set equals the set inferred from every entry of `root`.
///
/// Returns `Ok(())` iff `declared` is exactly the inferred set. Otherwise a
/// [`CliError::CapabilityMismatch`] naming the capabilities used but not
/// declared and those declared but not used. This is the primitive SP2 (manifest
/// generation) and SP4 (sandbox configuration) consume to reject a drifted or
/// under-declared manifest.
///
/// # Errors
/// [`CliError::Pipeline`] / [`CliError::Io`] when an entry cannot be lowered, or
/// [`CliError::CapabilityMismatch`] on a set mismatch.
pub fn verify_capabilities(
    root: &ProjectRoot,
    declared: &std::collections::BTreeSet<ipe_ir::Capability>,
) -> Result<(), CliError> {
    let inferred = target_capabilities(&AnalysisTarget::Project(root))?;
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
/// What is disclosed is what the package's OWN code reaches. Every package
/// module (and every FFI interface module) is a root: its functions are the
/// consumer-callable surface, called locally or not. An injected compiled-source
/// stdlib module is not: it contributes only the functions a root reaches over
/// the call graph, so an imported stdlib module whose effectful exports the
/// package never calls discloses nothing. Import-derived capabilities (`unsafe`,
/// `js-port:<axis>`) are attributed to the importing module and disclosed when
/// that module is a package module or a reached stdlib module (see
/// [`package_reached_capabilities`]).
///
/// Each discovered module is lowered as its own entry (with every sibling source
/// present, so cross-module imports resolve) and their inferred capabilities are
/// unioned. Inference fails closed: when ANY entry fails to lower, the package
/// is refused and nothing is disclosed, because a union over only the entries
/// that lowered would silently drop the failing entry's capabilities from the
/// consumer's consent surface. Every entry links the WHOLE package source tree,
/// exactly as `ipe dev build` does, so a module that does not compile at all (a
/// name or type error, imported or not) fails every entry and is refused the
/// same way.
///
/// # Errors
/// [`CliError::Pipeline`] / [`CliError::Io`] when the package cannot be read or
/// any entry fails to lower; the diagnostic is framed against the module that
/// owns it.
pub fn infer_package_capabilities(
    manifest_path: &Path,
) -> Result<std::collections::BTreeSet<ipe_ir::Capability>, CliError> {
    let package = PackageSourceSet::read(manifest_path)?;
    infer_package_capabilities_in(&ipe_db::IpeDatabase::new(), &package)
}

/// Every source a package's build and capability inference see, plus its entry modules.
///
/// Sources are the package's own modules plus the compiled-source stdlib closure
/// and FFI interface modules the build injects; the FFI emission inputs (the
/// `src/ffi.rs` bindings text among them) are computed in the same step. The
/// build ([`super::build_from_sources`]) and capability inference
/// ([`infer_package_capabilities_in`]) consume one value of this type, so the
/// bytes a capability verdict judges are the bytes that are emitted.
#[derive(Clone, Debug)]
pub struct PackageSourceSet {
    sources: BTreeMap<Vec<String>, (PathBuf, String)>,
    entries: Vec<project::DiscoveredModule>,
    injected: std::collections::BTreeSet<Vec<String>>,
    ffi_injected: std::collections::BTreeSet<Vec<String>>,
    ffi_emit: Option<ipe_backend_rust::FfiEmit>,
}

/// The parts of a [`PackageSourceSet`] the compile core consumes.
pub struct SourceSetParts {
    /// Every module source, injected ones included.
    pub sources: BTreeMap<Vec<String>, (PathBuf, String)>,
    /// The compiled-source stdlib module paths the driver injected.
    pub injected: std::collections::BTreeSet<Vec<String>>,
    /// The FFI interface module paths the driver injected.
    pub ffi_injected: std::collections::BTreeSet<Vec<String>>,
    /// The FFI emission inputs, when any crate is installed.
    pub ffi_emit: Option<ipe_backend_rust::FfiEmit>,
}

/// A module-source map with the modules discovered for it.
pub type ReadModules = (
    BTreeMap<Vec<String>, (PathBuf, String)>,
    Vec<project::DiscoveredModule>,
);

impl PackageSourceSet {
    /// Read the package rooted at `manifest_path` from disk, one bounded read per module.
    ///
    /// The working-tree reader for a single-shot command; a gate judges a
    /// [`project::PackageSnapshot`] through [`PackageSourceSet::from_snapshot`].
    ///
    /// # Errors
    /// [`CliError::Io`] / manifest errors when the package cannot be read.
    pub fn read(manifest_path: &Path) -> Result<Self, CliError> {
        let manifest = project::parse_manifest(manifest_path)?;
        let (sources, entries) = read_package_modules(&manifest)?;
        Self::assemble(sources, entries, manifest_path)
    }

    /// The source set of a captured package: its modules as the snapshot holds them, never re-read.
    ///
    /// # Errors
    /// The FFI catalog errors of [`ffi::prepare_ffi`].
    pub fn from_snapshot(snapshot: &project::PackageSnapshot) -> Result<Self, CliError> {
        Self::assemble(
            snapshot.sources().clone(),
            snapshot.modules().to_vec(),
            &snapshot_manifest_path(snapshot),
        )
    }

    /// The source set of the test program `view`: its universe as the snapshot holds it, never re-read.
    ///
    /// Nothing is injected or prepared again: the stdlib closure and the FFI
    /// preparation are the ones the view was minted with, so the test build
    /// binds the one catalog the snapshot read.
    #[must_use]
    pub fn from_test_view(view: &TestView) -> Self {
        let mut sources = BTreeMap::new();
        let mut injected = std::collections::BTreeSet::new();
        let mut entries = Vec::new();
        for (module, held) in view.modules() {
            if held.origin() == SourceOrigin::Stdlib {
                injected.insert(module.clone());
            }
            if module == view.entry() {
                entries.push(project::DiscoveredModule::user(
                    held.path().to_path_buf(),
                    module.clone(),
                ));
            }
            sources.insert(
                module.clone(),
                (held.path().to_path_buf(), held.text().to_owned()),
            );
        }
        Self {
            sources,
            entries,
            injected,
            ffi_injected: view.ffi().injected.clone(),
            ffi_emit: view.ffi().emit.clone(),
        }
    }

    /// Inject the compiled-source stdlib closure and the FFI interface modules into `sources`.
    ///
    /// `blame_path` is the project manifest or entry file the FFI catalog
    /// search walks up from.
    ///
    /// # Errors
    /// The FFI catalog errors of [`ffi::prepare_ffi`].
    pub fn assemble(
        mut sources: BTreeMap<Vec<String>, (PathBuf, String)>,
        mut entries: Vec<project::DiscoveredModule>,
        blame_path: &Path,
    ) -> Result<Self, CliError> {
        // `injected` is the driver's unforgeable record of which module paths
        // are trusted stdlib source, the only inputs that earn
        // `ModuleOrigin::EmbeddedStdlib`.
        let injected = project::inject_compiled_std_closure(&mut sources, &mut entries);
        // The catalog-load, nominal-unification, interface-inject and
        // emit-assemble sequence `watch` and `lsp` share.
        let ffi = ffi::prepare_ffi(&mut sources, blame_path)?;
        Ok(Self {
            sources,
            entries,
            injected,
            ffi_injected: ffi.injected,
            ffi_emit: ffi.emit,
        })
    }

    /// The `src/ffi.rs` text the build writes, when the package binds any crate.
    #[must_use]
    pub fn bindings_source(&self) -> Option<&str> {
        self.ffi_emit
            .as_ref()
            .map(|emit| emit.bindings_source.as_str())
    }

    /// Whether `module_path` is one of the module sources.
    #[must_use]
    pub fn has_module(&self, module_path: &[String]) -> bool {
        self.sources.contains_key(module_path)
    }

    /// The parts the compile core consumes.
    #[must_use]
    pub fn into_parts(self) -> SourceSetParts {
        SourceSetParts {
            sources: self.sources,
            injected: self.injected,
            ffi_injected: self.ffi_injected,
            ffi_emit: self.ffi_emit,
        }
    }

    /// The module path of every module lowered as an inference entry.
    pub fn entry_module_paths(&self) -> impl Iterator<Item = &[String]> {
        self.entries
            .iter()
            .map(crate::project::DiscoveredModule::module_path)
    }

    /// Number of modules in the source graph (entries plus injected modules).
    #[must_use]
    pub fn module_count(&self) -> usize {
        self.sources.len()
    }

    /// The same source graph with `module_path` as its only entry — the
    /// single-entry view whose capability sets [`infer_package_capabilities_in`]
    /// unions over every entry.
    #[must_use]
    pub fn restricted_to_entry(&self, module_path: &[String]) -> Self {
        Self {
            sources: self.sources.clone(),
            entries: self
                .entries
                .iter()
                .filter(|m| m.module_path() == module_path)
                .cloned()
                .collect(),
            injected: self.injected.clone(),
            ffi_injected: self.ffi_injected.clone(),
            ffi_emit: self.ffi_emit.clone(),
        }
    }
}

/// The `package.ipe` path of a captured package, the FFI catalog search's start.
#[must_use]
pub fn snapshot_manifest_path(snapshot: &project::PackageSnapshot) -> PathBuf {
    snapshot
        .manifest()
        .root
        .join(crate::package_manifest::PACKAGE_IPE)
}

/// Read every module under `manifest`'s source root, one bounded read each.
///
/// # Errors
/// [`CliError::Io`] when the source root cannot be walked or a module read.
pub fn read_package_modules(manifest: &project::ProjectManifest) -> Result<ReadModules, CliError> {
    let entries = project::discover_modules(&manifest.src_root)?;
    let mut sources: BTreeMap<Vec<String>, (PathBuf, String)> = BTreeMap::new();
    for m in &entries {
        let src = crate::io_bounded::read_walked_source(m.path())?;
        sources.insert(m.module_path().to_vec(), (m.path().to_path_buf(), src));
    }
    Ok((sources, entries))
}

/// [`infer_package_capabilities`] over one caller-supplied database.
///
/// Every entry is lowered against ONE shared [`ipe_db::SourceRoot`], so each
/// module's per-file queries (parse, canonicalize, interface) run once for the
/// whole package rather than once per entry.
///
/// Determinism: an entry's capability set is a function of its
/// `(root, entry)` query key alone. Symbol numbering on the shared interner
/// varies with demand order, but no capability depends on a symbol's number,
/// and the fresh-name avoid-set is the build's own (the identifier words of the
/// whole root), so each entry lowers exactly as a cold build over the same root
/// would. Entries are visited in the fixed [`PackageSourceSet`] order, and the
/// union is order-independent.
///
/// # Errors
/// [`CliError::Pipeline`] when any entry fails to lower (the entry `Main`'s
/// diagnostic when it fails, else the first failure), framed against the
/// module that owns it; [`CliError::Usage`] when the package has no module at
/// all.
pub fn infer_package_capabilities_in(
    db: &ipe_db::IpeDatabase,
    package: &PackageSourceSet,
) -> Result<std::collections::BTreeSet<ipe_ir::Capability>, CliError> {
    let source_root = create_source_root(
        db,
        &package.sources,
        &package.injected,
        &package.ffi_injected,
    );

    // The fresh-name collision universe the build path sets: the identifier
    // words of every module in the root — a pure function of the source inputs,
    // so the lowering pools mint the same names whatever entries ran before on
    // this shared interner. Set before the first `lower_program` executes; the
    // guard is released at the end of the statement, before any further query.
    let mut fresh_avoid: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for file in source_root.files(db).values() {
        fresh_avoid.extend(ipe_db::identifier_words(db, *file).iter().cloned());
    }
    ipe_db::Db::interner(db).lock().set_fresh_avoid(fresh_avoid);

    // The fold consumes every entry (never short-circuits), so each entry is
    // lowered exactly once and the surfaced refusal is the most actionable one.
    aggregate_entry_inferences(
        package
            .entries
            .iter()
            .map(|m| (m.provenance(), infer_entry(db, source_root, package, m))),
    )
}

/// One entry's capability-inference outcome: its capability set, or the
/// refusal that blocks the whole package.
type EntryInference = Result<std::collections::BTreeSet<ipe_ir::Capability>, CliError>;

/// How early an entry's refusal is surfaced when several entries fail.
///
/// The user's `Main` first, then other user modules, then an injected stdlib
/// module. A stdlib module failing to lower on its own is a compiler defect the
/// author cannot act on, so a user diagnostic outranks it; it still refuses the
/// package, because the stdlib is trusted to lower, not exempt from disclosure.
const fn refusal_rank(provenance: project::ModuleProvenance) -> u8 {
    match provenance {
        project::ModuleProvenance::User(project::EntryRole::Main) => 0,
        project::ModuleProvenance::User(project::EntryRole::Library) => 1,
        project::ModuleProvenance::EmbeddedStdlib => 2,
    }
}

/// Lower one package module as its own entry and infer its capabilities.
///
/// A lowering failure is a refusal framed against the module that owns it; an
/// entry with no source file in the root is a refusal too, never a skip.
fn infer_entry(
    db: &ipe_db::IpeDatabase,
    source_root: ipe_db::SourceRoot,
    package: &PackageSourceSet,
    module: &project::DiscoveredModule,
) -> EntryInference {
    let Some(entry_file) = source_root.files(db).get(module.module_path()).copied() else {
        return Err(CliError::Pipeline {
            file: module.path().to_path_buf(),
            src: package
                .sources
                .get(module.module_path())
                .map(|(_, s)| s.clone())
                .unwrap_or_default(),
            diag: Box::new(Diagnostic::CompilerBug {
                where_: "ipe.infer_package_capabilities",
                detail: format!(
                    "entry module {} has no source file in the package root",
                    module.module_path().join(".")
                ),
            }),
        });
    };
    match ipe_db::lower_program(db, source_root, entry_file) {
        Ok(program) => Ok(package_reached_capabilities(
            db,
            source_root,
            entry_file,
            package,
            program,
        )),
        Err(err) => Err(attribute_entry_lowering_error(
            db,
            source_root,
            package,
            module,
            entry_file,
            err.clone(),
        )),
    }
}

/// The capabilities one lowered entry discloses for the package: what the
/// package's own modules reach, never an unreached injected stdlib module's.
///
/// Kernel-derived capabilities come from [`ipe_lower::capabilities_reached_from`]
/// seeded at every function whose home is not an injected stdlib module. An
/// import-derived capability belongs to the module whose source imports it and
/// is disclosed when that module is a package module or a stdlib module the
/// roots reach; a module whose canonical form cannot be read falls back to the
/// whole-program import facts (fail closed). A constructed `customElement`
/// handle anywhere in the linked program still discloses `custom-element`,
/// exactly as [`capabilities_including_served_widgets`] does, since its asset
/// is served regardless of reachability.
fn package_reached_capabilities(
    db: &ipe_db::IpeDatabase,
    source_root: ipe_db::SourceRoot,
    entry_file: ipe_db::SourceFile,
    package: &PackageSourceSet,
    program: &ipe_ir::Program,
) -> std::collections::BTreeSet<ipe_ir::Capability> {
    let (mut caps, reached_homes) = {
        let interner = ipe_db::Db::interner(db).lock();
        // An injected path with a never-interned segment is the home of no
        // function, so dropping it cannot turn a stdlib function into a root.
        let stdlib_homes: std::collections::BTreeSet<ipe_ir::ModPath> = package
            .injected
            .iter()
            .filter_map(|path| {
                path.iter()
                    .map(|segment| interner.lookup(segment))
                    .collect::<Option<Vec<_>>>()
                    .map(ipe_ir::ModPath)
            })
            .collect();
        let reached = ipe_lower::capabilities_reached_from(program, &interner, |home| {
            !stdlib_homes.contains(home)
        });
        let reached_homes: std::collections::BTreeSet<Vec<String>> = reached
            .reached_homes
            .iter()
            .filter_map(|home| {
                home.0
                    .iter()
                    .map(|segment| interner.resolve(*segment).map(str::to_owned))
                    .collect::<Option<Vec<_>>>()
            })
            .collect();
        drop(interner);
        (reached.capabilities, reached_homes)
    };

    for (path, file) in source_root.files(db) {
        if package.injected.contains(path) && !reached_homes.contains(path) {
            continue;
        }
        let canonical = ipe_db::canonicalize(db, source_root, *file).clone();
        let (imports_unsafe, web) = canonical.as_ref().map_or_else(
            |_| {
                (
                    program.imports_unsafe_submodule,
                    &program.imported_web_capabilities,
                )
            },
            |c| {
                (
                    c.module.imports_unsafe_submodule,
                    &c.module.imported_web_capabilities,
                )
            },
        );
        if imports_unsafe {
            caps.insert(ipe_ir::Capability::Unsafe);
        }
        caps.extend(web.iter().map(|w| ipe_ir::Capability::JsPort(*w)));
    }

    if program_constructs_a_widget(db, source_root, entry_file) {
        caps.insert(ipe_ir::Capability::CustomElement);
    }
    caps
}

/// Fold every entry's outcome into the package's disclosed capability set.
///
/// Fails closed: any refused entry refuses the whole package, since a union
/// over only the entries that lowered would under-disclose the consumer's
/// consent surface. An injected stdlib entry is folded under the same rule as
/// a user entry; its provenance only lowers the precedence of its refusal (see
/// [`refusal_rank`]), ties going to the first in entry order.
///
/// # Errors
/// The selected entry refusal; [`CliError::Usage`] when there is no entry.
fn aggregate_entry_inferences(
    outcomes: impl IntoIterator<Item = (project::ModuleProvenance, EntryInference)>,
) -> Result<std::collections::BTreeSet<ipe_ir::Capability>, CliError> {
    let mut union: std::collections::BTreeSet<ipe_ir::Capability> =
        std::collections::BTreeSet::new();
    let mut refusal: Option<(u8, CliError)> = None;
    let mut any_entry = false;
    for (provenance, outcome) in outcomes {
        any_entry = true;
        match outcome {
            Ok(capabilities) => union.extend(capabilities),
            Err(err) => {
                let rank = refusal_rank(provenance);
                if refusal.as_ref().is_none_or(|(held, _)| rank < *held) {
                    refusal = Some((rank, err));
                }
            }
        }
    }
    match (refusal, any_entry) {
        (Some((_, err)), _) => Err(err),
        (None, true) => Ok(union),
        (None, false) => Err(CliError::Usage(
            text::msg::package_capability_inference_no_module(),
        )),
    }
}

/// Frame one entry's lowering failure against the module that OWNS it.
///
/// The build's own attribution: a canon error is blamed on its own module's
/// file via [`attribute_canon_errors`] (the root holds every package module, so
/// an unimported sibling that fails to canonicalize fails every entry, exactly
/// as `ipe dev build` refuses it); a post-link error goes through
/// [`attribute_post_link_error`]. Demanded after `lower_program`, so every
/// query here is a memo hit.
fn attribute_entry_lowering_error(
    db: &ipe_db::IpeDatabase,
    source_root: ipe_db::SourceRoot,
    package: &PackageSourceSet,
    entry: &project::DiscoveredModule,
    entry_file: ipe_db::SourceFile,
    err: ipe_db::PipelineError,
) -> CliError {
    if let Err(canon_err) =
        attribute_canon_errors(db, source_root, &package.sources, entry_file, entry.path())
    {
        return canon_err;
    }
    let entry_source = (
        entry.path().to_path_buf(),
        package
            .sources
            .get(entry.module_path())
            .map(|(_, s)| s.clone())
            .unwrap_or_default(),
    );
    let home_to_source = home_to_source_map(ipe_db::Db::interner(db), &package.sources);
    match (ipe_db::linked_program(db, source_root, entry_file), err) {
        (Ok(linked), err) => {
            attribute_post_link_error(&linked.module, &home_to_source, &entry_source, err)
        }
        (Err(_), ipe_db::PipelineError::Infer(infer)) => {
            frame_infer_error(&home_to_source, &entry_source, infer)
        }
        (Err(_), ipe_db::PipelineError::Lower(diag, home)) => {
            // A link failure has no linked program to scan: frame the lowering
            // diagnostic against its home module when known, else the entry.
            let (file, src) = home_to_source.get(&home).cloned().unwrap_or(entry_source);
            CliError::Pipeline {
                file,
                src,
                diag: Box::new(diag),
            }
        }
    }
}

// ===========================================================================
// `fix` / `--fix` — apply machine-applicable suggestions
// ===========================================================================

/// What one build-identical check of the fix target raised.
#[derive(Debug)]
pub enum FixCheck {
    /// The program compiles cleanly.
    Clean,
    /// The first diagnostic is owned by the fix target itself.
    InEntry {
        /// The source the diagnostic was framed against.
        src: String,
        /// The diagnostic.
        diag: Box<Diagnostic>,
    },
    /// The first diagnostic is owned by another module of the build.
    Elsewhere {
        /// The file that owns the diagnostic.
        file: PathBuf,
        /// The diagnostic.
        diag: Box<Diagnostic>,
    },
}

/// Run [`lowering_check_query`] over `graph` and say which file owns its first diagnostic.
///
/// `entry_real` is the canonical path of the fix target; a diagnostic is the
/// target's own only when its attributed file canonicalises to it.
///
/// # Errors
/// Any refusal that is not a compiler diagnostic, unchanged.
fn run_fix_check(
    graph: &SourceGraph,
    blame_path: &Path,
    entry_real: &Path,
) -> Result<FixCheck, CliError> {
    match graph.run_attributed(blame_path, lowering_check_query) {
        Ok(()) => Ok(FixCheck::Clean),
        Err(CliError::Pipeline { file, src, diag }) => {
            let owned_by_entry = fs::canonicalize(&file).is_ok_and(|real| real == entry_real);
            Ok(if owned_by_entry {
                FixCheck::InEntry { src, diag }
            } else {
                FixCheck::Elsewhere { file, diag }
            })
        }
        Err(other) => Err(other),
    }
}

/// Whether a patched program may replace the file it was diagnosed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchVerdict {
    /// The answered diagnostic is gone and nothing new precedes the edit.
    Accept,
    /// The patched program still raises the answered diagnostic.
    StillRaised,
    /// The patched program no longer parses.
    NoLongerParses,
    /// The patched program raises a name-resolution error at or before the edit.
    NewResolutionError,
}

/// Judge the re-check of a patched program against the diagnostic the patch answered.
///
/// `edited_end` is the end, in patched coordinates, of the last edit. A
/// diagnostic is the answered one when its code and span origin match. A
/// resolution error owned by another module is never provably unrelated to
/// the edit, so it refuses wherever it sits.
#[must_use]
pub fn judge_patch(answered: &Diagnostic, edited_end: u32, after: &FixCheck) -> PatchVerdict {
    let (diag, in_entry) = match after {
        FixCheck::Clean => return PatchVerdict::Accept,
        FixCheck::InEntry { diag, .. } => (diag, true),
        FixCheck::Elsewhere { diag, .. } => (diag, false),
    };
    let family = diag.code().family();
    if matches!(family, ipe_diagnostics::Family::Parse) {
        return PatchVerdict::NoLongerParses;
    }
    if in_entry
        && diag.code() == answered.code()
        && diag.primary_span().lo == answered.primary_span().lo
    {
        return PatchVerdict::StillRaised;
    }
    let at_or_before_edit = !in_entry || diag.primary_span().lo <= edited_end;
    if matches!(family, ipe_diagnostics::Family::Name) && at_or_before_edit {
        return PatchVerdict::NewResolutionError;
    }
    PatchVerdict::Accept
}

/// The end, in the patched text, of the right-most of the non-overlapping `edits`.
///
/// An offset past `u32::MAX` saturates, so a judgement against it errs toward refusal.
#[must_use]
pub fn patched_edit_end(edits: &[Suggestion]) -> u32 {
    let mut ascending: Vec<&Suggestion> = edits.iter().collect();
    ascending.sort_by_key(|s| s.span.lo);
    let mut shift: i64 = 0;
    let mut end: i64 = 0;
    for s in ascending {
        let replaced = i64::from(s.span.hi).saturating_sub(i64::from(s.span.lo));
        let inserted = i64::try_from(s.replacement.len()).unwrap_or(i64::MAX);
        end = i64::from(s.span.lo)
            .saturating_add(shift)
            .saturating_add(inserted);
        shift = shift.saturating_add(inserted.saturating_sub(replaced));
    }
    u32::try_from(end).unwrap_or(u32::MAX)
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
/// if any span is out of bounds, not on a UTF-8 char boundary, or holds text
/// other than the suggestion's `replaces`. Never indexes raw bytes.
#[must_use]
pub fn apply_fixes(src: &str, fixes: &[Suggestion]) -> Option<String> {
    let mut out = src.to_owned();
    for s in fixes {
        let lo = usize::try_from(s.span.lo).ok()?;
        let hi = usize::try_from(s.span.hi).ok()?;
        if out.get(lo..hi) != Some(&*s.replaces) {
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

/// The fix command/flow: diagnose what `file` names in `root` with the build's
/// own resolution and apply the machine-applicable suggestions of its first
/// diagnostic.
///
/// The named module is analysed as `ipe type-check` analyses it, over the one
/// [`SourceSnapshot`](crate::source_snapshot::SourceSnapshot) of `root` —
/// never by a reduced single-module resolution, so a name the build binds
/// through an import is never "corrected". No file names every entry of the
/// project, each fixed in turn. A diagnostic another module owns is reported,
/// never patched.
///
/// `auto` (set by `--yes` / `--fix`) is durable authorization to apply every
/// edit without prompting; otherwise each edit is confirmed interactively on
/// stdin. The patch is never silent: every applied or skipped edit is reported
/// on `w`. The patched text is re-checked by the same resolution before it
/// replaces the file ([`judge_patch`]), and the file is replaced only while it
/// still holds the bytes that were diagnosed.
///
/// Writes go through a temp file + atomic rename.
///
/// # Errors
/// The refusal of a project context that cannot be built (an unreadable or
/// malformed manifest, a module that cannot be read); [`CliError::Io`] on a
/// filesystem failure.
pub fn apply_fixes_cmd<W: Write>(
    root: &ProjectRoot,
    file: Option<&FileArg>,
    auto: bool,
    w: &mut W,
) -> Result<(), CliError> {
    let target = analysis_target(root, file)?;
    for graph in analysis_graphs(&target)? {
        fix_entry(graph, auto, w)?;
    }
    Ok(())
}

/// Fix the entry of one source graph; every report names the entry's file.
fn fix_entry<W: Write>(mut graph: SourceGraph, auto: bool, w: &mut W) -> Result<(), CliError> {
    let blame_path = graph.entry_path().to_path_buf();
    let entry = blame_path.as_path();
    let entry_real = fs::canonicalize(&blame_path).map_err(|e| io_err(&blame_path, e))?;
    let source = graph.entry_file.text(&graph.db).clone();
    let first = run_fix_check(&graph, &blame_path, &entry_real)?;
    let Some(diag) = answerable_diagnostic(first, &source, entry, w)? else {
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
    let chosen = choose_edits(&source, &selected, entry, auto, w)?;
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
        writeln!(w, "{PATCH_NO_LONGER_PARSES}").map_err(|e| io_err(entry, e))?;
        return Ok(());
    }

    // Second gate: the patched text, re-checked in memory by the same
    // resolution over the same universe, must have answered its diagnostic.
    ipe_db::set_text_if_changed(&mut graph.db, graph.entry_file, &patched);
    let after = run_fix_check(&graph, &blame_path, &entry_real)?;
    if let Some(refusal) = patch_refusal(&diag, &chosen, &after) {
        writeln!(w, "{refusal}").map_err(|e| io_err(entry, e))?;
        return Ok(());
    }

    let IfUnchanged::Written(backup) =
        rewrite_user_file_if_unchanged(&entry_real, &source, &patched, RewriteKind::Lossy)?
    else {
        writeln!(
            w,
            "fix: {} changed while it was being fixed — file left unchanged",
            entry.display()
        )
        .map_err(|e| io_err(entry, e))?;
        return Ok(());
    };
    writeln!(
        w,
        "fix: applied {} edit(s) to {}",
        chosen.len(),
        entry.display()
    )
    .map_err(|e| io_err(entry, e))?;
    if let Some(backup) = backup {
        writeln!(w, "fix: original kept at {}", backup.display()).map_err(|e| io_err(entry, e))?;
    }
    Ok(())
}

/// The diagnostic `ipe fix` may answer from `check`, or `None` once it has said why there is none.
///
/// Only a diagnostic the fix target owns, framed against exactly the `source`
/// that was diagnosed, is answerable.
fn answerable_diagnostic<W: Write>(
    check: FixCheck,
    source: &str,
    entry: &Path,
    w: &mut W,
) -> Result<Option<Box<Diagnostic>>, CliError> {
    let refusal = match check {
        FixCheck::InEntry { src, diag } if src == source => return Ok(Some(diag)),
        FixCheck::Clean => format!("fix: nothing to do — {} compiles cleanly", entry.display()),
        FixCheck::InEntry { .. } => format!(
            "fix: the diagnosed source is not {} — file left unchanged (please report)",
            entry.display()
        ),
        FixCheck::Elsewhere { file, diag } => format!(
            "fix: the first diagnostic [{}] is in {}, not {} — no edits applied",
            diag.code().as_str(),
            file.display(),
            entry.display()
        ),
    };
    writeln!(w, "{refusal}").map_err(|e| io_err(entry, e))?;
    Ok(None)
}

/// The `selected` edits to apply: all of them under `auto`, else each one the user confirms.
fn choose_edits<W: Write>(
    source: &str,
    selected: &[Suggestion],
    entry: &Path,
    auto: bool,
    w: &mut W,
) -> Result<Vec<Suggestion>, CliError> {
    let mut chosen: Vec<Suggestion> = Vec::new();
    for s in selected {
        let lo = usize::try_from(s.span.lo).unwrap_or(usize::MAX);
        let hi = usize::try_from(s.span.hi).unwrap_or(usize::MAX);
        let original = source.get(lo..hi).unwrap_or("");
        let (line, col) = line_col(source, lo);
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
    Ok(chosen)
}

/// Why the re-check `after` of a patch made of `chosen` refuses it, or `None` when it may land.
fn patch_refusal(answered: &Diagnostic, chosen: &[Suggestion], after: &FixCheck) -> Option<String> {
    match judge_patch(answered, patched_edit_end(chosen), after) {
        PatchVerdict::Accept => None,
        PatchVerdict::NoLongerParses => Some(PATCH_NO_LONGER_PARSES.to_owned()),
        PatchVerdict::StillRaised => Some(format!(
            "fix: the edit leaves [{}] unresolved — file left unchanged",
            answered.code().as_str()
        )),
        PatchVerdict::NewResolutionError => Some(format!(
            "fix: the edit raises a new resolution error [{}] — file left unchanged",
            first_code(after)
        )),
    }
}

/// The refusal reported for a patch whose result no longer parses.
const PATCH_NO_LONGER_PARSES: &str =
    "fix: patched source no longer parses — rolled back, file left unchanged";

/// The wire code of a check's first diagnostic, or the empty string when it raised none.
fn first_code(check: &FixCheck) -> &'static str {
    match check {
        FixCheck::Clean => "",
        FixCheck::InEntry { diag, .. } | FixCheck::Elsewhere { diag, .. } => diag.code().as_str(),
    }
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

/// Replace a user-owned file atomically.
///
/// Used for `ipe.lock`, a rewritten source, and a health config.
///
/// A sibling temp file is created exclusively and renamed over `target`
/// (atomic on a single filesystem); on failure the temp file is removed.
/// Build products never come here — they go through
/// [`crate::output_dir::OwnedPath`]. Retries once, recreating the parent
/// directory, when the write or rename fails with `NotFound`.
///
/// # Errors
/// [`CliError::Io`] on a filesystem failure.
pub fn write_atomic(target: &Path, contents: &str) -> Result<(), CliError> {
    // Unique per process, call, and instant: the temp file is created
    // exclusively, so a stale leftover of an earlier run can never collide.
    static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = target.parent().filter(|p| !p.as_os_str().is_empty());
    let name = target.file_name().map_or_else(
        || String::from("source.ipe"),
        |n| n.to_string_lossy().into_owned(),
    );
    let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let tmp_name = format!(".{name}.ipec-fix.{}.{seq}.{nanos}.tmp", std::process::id());
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

/// Write `contents` to `tmp`, then rename it over `target`.
///
/// On a rename failure the temp file is removed so no debris is left behind.
///
/// `tmp` is created exclusively (`create_new`): a pre-existing file or symlink
/// at that name is never truncated or written through. The replacement keeps
/// `target`'s permission bits, so a rewrite never changes a file's mode.
pub fn write_and_rename(tmp: &Path, target: &Path, contents: &str) -> Result<(), CliError> {
    let written = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp)
        .and_then(|mut file| {
            file.write_all(contents.as_bytes())?;
            if let Ok(meta) = fs::metadata(target) {
                file.set_permissions(meta.permissions())?;
            }
            Ok(())
        });
    if let Err(e) = written {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            let _ = fs::remove_file(tmp);
        }
        return Err(io_err(tmp, e));
    }
    if let Err(e) = fs::rename(tmp, target) {
        let _ = fs::remove_file(tmp);
        return Err(io_err(target, e));
    }
    Ok(())
}

/// Whether rewriting a user file can lose information the user may want back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewriteKind {
    /// Layout only, proven meaning-preserving (`ipe fmt`'s round-trip guard).
    Lossless,
    /// A change to the code itself (`ipe fix`, `lint --fix`, `init --force`).
    ///
    /// The original is copied to a backup first.
    Lossy,
}

/// The directory, beside a rewritten file, that holds ipe's backup copies.
pub const BACKUP_DIR: &str = ".ipe-backup";

/// The most backup names tried for one file within the same nanosecond.
const BACKUP_NAME_ATTEMPTS: u32 = 16;

/// Rewrite a user-owned file the user named explicitly.
///
/// A symlink is resolved to the real file (the file the user edits); the
/// original is copied to a backup first when the rewrite is
/// [`RewriteKind::Lossy`]; then the file is replaced atomically — never
/// truncated in place, so a crash mid-write leaves the original intact. Returns
/// the backup path when one was made.
///
/// # Errors
/// [`CliError::Io`] when the backup or the replacement fails; the original is
/// untouched in either case.
pub fn rewrite_user_file(
    path: &Path,
    contents: &str,
    kind: RewriteKind,
) -> Result<Option<PathBuf>, CliError> {
    let real = fs::canonicalize(path).map_err(|e| io_err(path, e))?;
    rewrite_real_file(&real, contents, kind)
}

/// A rewrite conditioned on the file still holding the bytes it was judged by.
#[derive(Debug, PartialEq, Eq)]
pub enum IfUnchanged {
    /// The file was replaced; carries the backup path when one was made.
    Written(Option<PathBuf>),
    /// The file no longer holds the expected bytes and was left as it is.
    Changed,
}

/// Rewrite the user-named file at `path` only while it still holds `expected`.
///
/// The file is re-read immediately before it is backed up and replaced, so an
/// edit made to it after it was judged is never overwritten.
///
/// # Errors
/// The re-read's own refusal; otherwise as [`rewrite_user_file`].
pub fn rewrite_user_file_if_unchanged(
    path: &Path,
    expected: &str,
    contents: &str,
    kind: RewriteKind,
) -> Result<IfUnchanged, CliError> {
    let real = fs::canonicalize(path).map_err(|e| io_err(path, e))?;
    let current = crate::io_bounded::read_user_named(&real, crate::io_bounded::SOURCE_CAP)?;
    if current != expected {
        return Ok(IfUnchanged::Changed);
    }
    rewrite_real_file(&real, contents, kind).map(IfUnchanged::Written)
}

/// Rewrite a user-owned file a directory walk under `root` reached.
///
/// As [`rewrite_user_file`], but the file must resolve inside `root`: a
/// symlink leading out of the project is refused, never followed.
///
/// # Errors
/// [`crate::output_dir::OutputRefusal::OutsideProject`] for a file escaping
/// `root`; otherwise as [`rewrite_user_file`].
pub fn rewrite_walked_file(
    root: &Path,
    path: &Path,
    contents: &str,
    kind: RewriteKind,
) -> Result<Option<PathBuf>, CliError> {
    let real = crate::output_dir::contained_in(root, path)?;
    rewrite_real_file(&real, contents, kind)
}

/// Back `real` up when `kind` is lossy, then replace it atomically.
fn rewrite_real_file(
    real: &Path,
    contents: &str,
    kind: RewriteKind,
) -> Result<Option<PathBuf>, CliError> {
    let backup = match kind {
        RewriteKind::Lossless => None,
        RewriteKind::Lossy => Some(backup_user_file(real)?),
    };
    write_atomic(real, contents)?;
    Ok(backup)
}

/// Copy `real` to `<its dir>/.ipe-backup/<name>.<nanos>.<n>`.
///
/// Each backup name is created exclusively, so no existing backup is replaced.
/// The copy is created owner-only and then given the original's permission
/// bits, so a private file never has a more readable backup, even briefly. A
/// symlinked `.ipe-backup` is refused.
///
/// # Errors
/// [`CliError::OutputRefused`] for a symlinked backup directory;
/// [`CliError::Io`] on any filesystem failure, or when every candidate name is
/// taken.
pub fn backup_user_file(real: &Path) -> Result<PathBuf, CliError> {
    let dir = real
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = real.file_name().map_or_else(
        || String::from("source"),
        |n| n.to_string_lossy().into_owned(),
    );
    let backup_dir = dir.join(BACKUP_DIR);
    if fs::symlink_metadata(&backup_dir).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(crate::output_dir::OutputRefusal::Symlink(backup_dir).into());
    }
    fs::create_dir_all(&backup_dir).map_err(|e| io_err(&backup_dir, e))?;
    let permissions = fs::metadata(real)
        .map_err(|e| io_err(real, e))?
        .permissions();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    for attempt in 0..BACKUP_NAME_ATTEMPTS {
        let dest = backup_dir.join(format!("{name}.{stamp}.{attempt}"));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&dest) {
            Ok(mut copy) => {
                let mut original = fs::File::open(real).map_err(|e| io_err(real, e))?;
                std::io::copy(&mut original, &mut copy).map_err(|e| io_err(&dest, e))?;
                copy.set_permissions(permissions)
                    .map_err(|e| io_err(&dest, e))?;
                return Ok(dest);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(io_err(&dest, e)),
        }
    }
    Err(io_err(
        &backup_dir,
        std::io::Error::from(std::io::ErrorKind::AlreadyExists),
    ))
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
        | Diagnostic::RegistryUnreachable { .. }
        | Diagnostic::TargetDirUnlinkable { .. }
        | Diagnostic::HostLinkerCannotOpenInput { .. } => ipe_diagnostics::Span::DUMMY,
    }
}

// ── Refusal gate unit tests ───────────────────────────────────────────────────
//
// These tests drive the fail-closed shape/permission gates WITHOUT a real
// project on disk: they pass `Some(declared)` so `classify_entry_shape` (which
// reads source files) is bypassed. Any rejected path that no test drives is one
// edit away from silently passing — pin them here.

#[cfg(test)]
mod installer_tag_tests {
    use super::*;

    #[test]
    fn installer_refused_where_unsupported() {
        assert!(matches!(
            installer_gate(InstallerSupport::Unsupported),
            Err(CliError::Usage(_))
        ));
    }

    #[test]
    fn installer_admitted_where_supported() {
        assert!(installer_gate(InstallerSupport::Supported).is_ok());
    }

    #[test]
    fn accepts_a_release_tag_and_normalises_it() {
        assert_eq!(parse_installer_tag(b"v0.2.5\n").as_deref(), Some("v0.2.5"));
        assert_eq!(
            parse_installer_tag(b"ipe-v0.2.5").as_deref(),
            Some("v0.2.5")
        );
        assert_eq!(
            parse_installer_tag(b"v1.0.0-rc.1+build.7\n").as_deref(),
            Some("v1.0.0-rc.1+build.7")
        );
    }

    #[test]
    fn refuses_oversize_input() {
        let mut raw = b"v1.0.0-".to_vec();
        raw.resize(UPGRADE_TAG_MAX_BYTES + 1, b'a');
        assert_eq!(parse_installer_tag(&raw), None);
    }

    #[test]
    fn refuses_garbage() {
        for raw in [
            &b""[..],
            b"\n",
            b"0.2.5",
            b"latest",
            b"v0.2",
            b" v0.2.5",
            b"v0.2.5 \n",
            b"v0.2.5\n\n",
            b"v0.2.5\nv9.9.9",
            b"v0.2.5\r\n",
            b"v0.2.5\x1b[2J",
            b"v\xff.2.5",
            b"ipe-ipe-v0.2.5",
        ] {
            assert_eq!(parse_installer_tag(raw), None, "accepted {raw:?}");
        }
    }
}

#[cfg(test)]
mod self_reinvocation_tests {
    use super::*;

    /// The mobile shell's wasm build re-invokes `ipe` with the argv of the
    /// verb its profile names, so the spelling comes from [`Verb`] alone.
    #[test]
    fn self_reinvocation_argv_from_verb() {
        assert_eq!(wasm_build_verb(BundleProfile::Dev).argv(), ["dev", "build"]);
        assert_eq!(
            wasm_build_verb(BundleProfile::Release).argv(),
            ["release", "build"]
        );
        for profile in [BundleProfile::Dev, BundleProfile::Release] {
            let verb = wasm_build_verb(profile);
            assert_eq!(verb.intent(), profile.build_intent(), "{verb}");
        }
    }
}

#[cfg(test)]
mod mobile_base_tests {
    use super::*;
    use ipe_runtime_rust::encoding::MountBase;

    /// Write a project whose `delivery.browser.basePath` is `base_path` and
    /// return its `package.ipe`. `base_path` is printable ASCII without `"` or
    /// `\`, so its Rust `{:?}` form is also its Ipê string literal.
    fn write_project(test_name: &str, base_path: &str) -> PathBuf {
        let root = ipe_test_temp::temp_root().join(format!("ipe_mobile_base_{test_name}"));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("src");
        std::fs::create_dir_all(&src).expect("create src/");
        std::fs::write(
            src.join("Main.ipe"),
            "module Main exposing (main)\nmain = 0\n",
        )
        .expect("write Main.ipe");
        let manifest = root.join(crate::package_manifest::PACKAGE_IPE);
        write_base_path(&manifest, base_path);
        manifest
    }

    fn write_base_path(manifest: &Path, base_path: &str) {
        std::fs::write(
            manifest,
            format!(
                "module Package exposing (package)\n\npackage =\n    {{ name = \"x\", \
                 delivery = {{ browser = {{ basePath = {base_path:?} }} }} }}\n"
            ),
        )
        .expect("write package.ipe");
    }

    fn base(raw: &str) -> MountBase {
        MountBase::parse(raw).expect("a legal mount base")
    }

    /// The stub build rewrites the manifest's base; the pack refuses, naming
    /// both bases, before any shell is laid out.
    #[test]
    fn mobile_pack_refuses_manifest_changed_during_build() {
        let manifest = write_project("changed", "/app");
        let planned = project::parse_manifest(&manifest)
            .expect("manifest")
            .delivery
            .browser
            .base;
        assert_eq!(planned, base("/app"));

        let result = build_under_fixed_base(&manifest, &planned, || {
            write_base_path(&manifest, "/v2");
            Ok(())
        });
        let _ = std::fs::remove_dir_all(manifest.parent().expect("project root"));

        let refusal = text::Message::relay(&pack::mobile::MobileRefusal::ManifestChanged {
            before: base("/app"),
            after: base("/v2"),
        });
        assert!(
            matches!(&result, Err(CliError::Usage(shown)) if *shown == refusal),
            "a base changed during the build must be refused, got {result:?}"
        );
    }

    /// An unchanged base passes once the build has run.
    #[test]
    fn mobile_pack_accepts_an_unchanged_base_after_the_build() {
        let manifest = write_project("unchanged", "/app");
        let built = std::cell::Cell::new(false);
        let result = build_under_fixed_base(&manifest, &base("/app"), || {
            built.set(true);
            Ok(())
        });
        let _ = std::fs::remove_dir_all(manifest.parent().expect("project root"));
        assert!(result.is_ok(), "{result:?}");
        assert!(built.get(), "the build step runs before the re-read");
    }
}

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
            matches!(&err, CliError::Usage(_)),
            "expected Usage, got {err:?}"
        );
        let CliError::Usage(msg) = err else {
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
            matches!(&err, CliError::Usage(_)),
            "expected Usage, got {err:?}"
        );
        let CliError::Usage(msg) = err else {
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
            matches!(&err, CliError::Usage(_)),
            "expected Usage, got {err:?}"
        );
        let CliError::Usage(msg) = err else {
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
        let wasm_on = project::WasmConfig::On(project::WasmBundle::new(project::WasmMode::Solo));
        let err = validate_mobile_shape(
            Some(project::EntryShape::Terminal),
            Path::new("."),
            &wasm_on,
        )
        .expect_err("Terminal shape must be refused for mobile");
        assert!(
            matches!(&err, CliError::Usage(_)),
            "expected Usage, got {err:?}"
        );
        let CliError::Usage(msg) = err else {
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
        let wasm_on = project::WasmConfig::On(project::WasmBundle::new(project::WasmMode::Solo));
        let err =
            validate_mobile_shape(Some(project::EntryShape::Program), Path::new("."), &wasm_on)
                .expect_err("Program shape must be refused for mobile");
        assert!(
            matches!(&err, CliError::Usage(_)),
            "expected Usage, got {err:?}"
        );
        let CliError::Usage(msg) = err else {
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
        let wasm_off = project::WasmConfig::Off;
        let err = validate_mobile_shape(Some(project::EntryShape::Web), Path::new("."), &wasm_off)
            .expect_err("Web shape without wasm must be refused for mobile");
        assert!(
            matches!(&err, CliError::Usage(_)),
            "expected Usage, got {err:?}"
        );
        let CliError::Usage(msg) = err else {
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
        let wasm_on = project::WasmConfig::On(project::WasmBundle::new(project::WasmMode::Solo));
        validate_mobile_shape(Some(project::EntryShape::Web), Path::new("."), &wasm_on)
            .expect("Web + wasm=spa must pass the mobile gate");
    }

    /// A `Web` shape with wasm mode `hydrate` also passes the mobile gate.
    #[test]
    fn mobile_gate_accepts_web_shape_with_wasm_hydrate() {
        let wasm_on = project::WasmConfig::On(project::WasmBundle::new(project::WasmMode::Hydrate));
        validate_mobile_shape(Some(project::EntryShape::Web), Path::new("."), &wasm_on)
            .expect("Web + wasm=hydrate must pass the mobile gate");
    }

    // ── Mobile capability classification ──────────────────────────────────────

    /// `Web` + wasm enabled -> `shape_is_web=true`, `wasm_enabled=true`.
    #[test]
    fn classify_mobile_cap_web_wasm_on() {
        let wasm_on = project::WasmConfig::On(project::WasmBundle::new(project::WasmMode::Solo));
        let cap = classify_mobile_spa_cap(Some(project::EntryShape::Web), Path::new("."), &wasm_on)
            .expect("classification must succeed");
        assert!(cap.shape_is_web, "Web shape must set shape_is_web");
        assert!(cap.wasm_enabled, "spa mode must set wasm_enabled");
    }

    /// `Terminal` + wasm enabled -> `shape_is_web=false`.
    #[test]
    fn classify_mobile_cap_terminal_wasm_on() {
        let wasm_on = project::WasmConfig::On(project::WasmBundle::new(project::WasmMode::Solo));
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
        let wasm_off = project::WasmConfig::Off;
        let cap =
            classify_mobile_spa_cap(Some(project::EntryShape::Web), Path::new("."), &wasm_off)
                .expect("classification must succeed");
        assert!(cap.shape_is_web, "Web shape must set shape_is_web");
        assert!(!cap.wasm_enabled, "`Off` must set wasm_enabled=false");
    }
}

// ── Capability-inference fold refusals ───────────────────────────────────────
//
// The fold over per-entry outcomes is the package's disclosure verdict: a
// failed entry must refuse the package, never shrink the disclosed set.

#[cfg(test)]
mod capability_fold_tests {
    use super::*;
    use ipe_ir::Capability;
    use std::collections::BTreeSet;

    const MAIN: project::ModuleProvenance =
        project::ModuleProvenance::User(project::EntryRole::Main);
    const SIBLING: project::ModuleProvenance =
        project::ModuleProvenance::User(project::EntryRole::Library);
    const STDLIB: project::ModuleProvenance = project::ModuleProvenance::EmbeddedStdlib;

    fn set(capabilities: &[Capability]) -> BTreeSet<Capability> {
        capabilities.iter().copied().collect()
    }

    /// A catalog refusal that names `entry`, so each fixture refusal is distinct.
    fn reason(entry: &str) -> crate::text::Message {
        crate::text::msg::publish_no_version(&entry)
    }

    fn refused(entry: &str) -> EntryInference {
        Err(CliError::Usage(reason(entry)))
    }

    /// One entry lowers with network access while its sibling fails to lower.
    ///
    /// The package is refused, and the lowered entry's set is not disclosed.
    #[test]
    fn a_failed_sibling_refuses_the_package_instead_of_under_disclosing() {
        let verdict = aggregate_entry_inferences([
            (MAIN, Ok(set(&[Capability::Network]))),
            (SIBLING, refused("sibling failed to lower")),
        ]);
        assert!(
            matches!(&verdict, Err(CliError::Usage(got)) if *got == reason("sibling failed to lower")),
            "expected the sibling's refusal, got {verdict:?}"
        );
    }

    /// A failed entry refuses the package whatever its position in entry order.
    #[test]
    fn a_failed_entry_refuses_regardless_of_order() {
        let verdict = aggregate_entry_inferences([
            (SIBLING, refused("first entry failed")),
            (MAIN, Ok(set(&[Capability::Network]))),
            (SIBLING, Ok(set(&[Capability::Unsafe]))),
        ]);
        assert!(
            matches!(&verdict, Err(CliError::Usage(got)) if *got == reason("first entry failed")),
            "expected the failed entry's refusal, got {verdict:?}"
        );
    }

    /// When several entries fail, the `Main` entry's refusal is surfaced.
    #[test]
    fn the_main_entry_refusal_is_preferred() {
        let verdict = aggregate_entry_inferences([
            (SIBLING, refused("sibling failed")),
            (MAIN, refused("main failed")),
            (SIBLING, refused("later sibling failed")),
        ]);
        assert!(
            matches!(&verdict, Err(CliError::Usage(got)) if *got == reason("main failed")),
            "expected the Main entry's refusal, got {verdict:?}"
        );
    }

    /// A failed injected stdlib entry refuses the package even when every user
    /// entry lowers: trusted stdlib is never exempt from the fail-closed fold.
    #[test]
    fn a_failed_stdlib_entry_refuses_the_package() {
        let verdict = aggregate_entry_inferences([
            (MAIN, Ok(set(&[Capability::Network]))),
            (STDLIB, refused("stdlib entry failed")),
            (SIBLING, Ok(set(&[]))),
        ]);
        assert!(
            matches!(&verdict, Err(CliError::Usage(got)) if *got == reason("stdlib entry failed")),
            "expected the stdlib entry's refusal, got {verdict:?}"
        );
    }

    /// A user entry's refusal outranks a stdlib entry's, whatever the order.
    #[test]
    fn a_user_refusal_is_preferred_over_a_stdlib_refusal() {
        let verdict = aggregate_entry_inferences([
            (STDLIB, refused("stdlib entry failed")),
            (SIBLING, refused("sibling failed")),
        ]);
        assert!(
            matches!(&verdict, Err(CliError::Usage(got)) if *got == reason("sibling failed")),
            "expected the user entry's refusal, got {verdict:?}"
        );
    }

    /// A package with no entry is refused, never disclosed as capability-free.
    #[test]
    fn a_package_without_entries_is_refused() {
        let verdict = aggregate_entry_inferences(std::iter::empty());
        assert!(
            matches!(verdict, Err(CliError::Usage(_))),
            "expected a refusal, got {verdict:?}"
        );
    }

    /// When every entry lowers, the disclosed set is the union of all entries.
    #[test]
    fn every_entry_lowered_discloses_the_union() {
        let verdict = aggregate_entry_inferences([
            (MAIN, Ok(set(&[Capability::Network]))),
            (SIBLING, Ok(set(&[Capability::Unsafe]))),
            (SIBLING, Ok(set(&[]))),
        ]);
        let expected: BTreeSet<Capability> = [Capability::Network, Capability::Unsafe]
            .into_iter()
            .collect();
        assert!(
            matches!(&verdict, Ok(set) if *set == expected),
            "expected the union {expected:?}, got {verdict:?}"
        );
    }
}

// A quiet test binary writes its summary and its own stderr to the CLI's
// stderr: neither stream is dropped, and nothing is held in the CLI's memory.

#[cfg(all(test, unix))]
mod test_binary_tests {
    use super::*;
    use crate::scratch::{ScratchDir, ScratchFile};

    /// A compiled test runner stood in for by the `sh` script `body`, inside `dir`.
    #[allow(clippy::expect_used)] // a fixture that cannot be written fails the test
    fn stub_binary(dir: &ScratchDir, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let bin = dir.path().join("runner");
        std::fs::write(&bin, format!("#!/bin/sh\n{body}\n")).expect("write the stub binary");
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))
            .expect("mark the stub binary executable");
        bin
    }

    /// Run `bin` quiet with a scratch file as the CLI's stderr; the outcome and what reached that file.
    #[allow(clippy::expect_used)] // a fixture that cannot be read fails the test
    fn run_quiet(bin: PathBuf) -> (Result<std::process::ExitStatus, CliError>, String) {
        let mut sink = ScratchFile::create("ipe-test-binary-stderr").expect("scratch sink");
        let ran = run_test_binary(bin, TestStdio::Quiet, || {
            sink.file.try_clone().expect("clone the sink handle")
        });
        let written = sink.read_all().expect("read the sink");
        (ran, String::from_utf8_lossy(&written).into_owned())
    }

    /// A quiet run keeps the binary off the stdin a machine consumer of the CLI holds.
    #[test]
    fn a_quiet_test_binary_reads_the_null_device() {
        assert!(matches!(
            test_binary_stdin(TestStdio::Quiet),
            InheritedInput::Null
        ));
        assert!(matches!(
            test_binary_stdin(TestStdio::Inherit),
            InheritedInput::Terminal
        ));
    }

    #[test]
    #[allow(clippy::expect_used)] // a fixture that cannot be created fails the test
    fn a_quiet_test_binary_stdout_reaches_the_cli_stderr() {
        let dir = ScratchDir::new("ipe-test-binary").expect("scratch dir");
        let (ran, written) = run_quiet(stub_binary(&dir, "printf 'summary-on-stdout'"));
        assert!(
            matches!(&ran, Ok(status) if status.success()),
            "the stub exits 0: {ran:?}"
        );
        assert!(
            written.contains("summary-on-stdout"),
            "the binary's stdout must reach the CLI's stderr, got {written:?}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)] // a fixture that cannot be created fails the test
    fn a_quiet_test_binary_keeps_its_stderr() {
        let dir = ScratchDir::new("ipe-test-binary").expect("scratch dir");
        let (ran, written) = run_quiet(stub_binary(&dir, "printf 'failure-on-stderr' >&2\nexit 3"));
        assert!(
            matches!(&ran, Ok(status) if status.code() == Some(3)),
            "the stub's own exit code is the outcome: {ran:?}"
        );
        assert!(
            written.contains("failure-on-stderr"),
            "the binary's stderr must reach the CLI's stderr, got {written:?}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)] // a fixture that cannot be created fails the test
    fn a_test_binary_that_cannot_start_is_an_io_error_naming_it() {
        let dir = ScratchDir::new("ipe-test-binary").expect("scratch dir");
        let absent = dir.path().join("absent-runner");
        let (ran, _) = run_quiet(absent.clone());
        let Err(CliError::Io { path, .. }) = ran else {
            assert!(matches!(ran, Err(CliError::Io { .. })), "got {ran:?}");
            return;
        };
        assert_eq!(path, absent);
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use ipe_ir::Capability;
    use std::collections::BTreeSet;

    /// A digest literal of `fill` hex digits.
    #[allow(clippy::expect_used)] // test fixture: the literal is a valid digest
    fn digest(fill: &str) -> index::Sha256Hex {
        let package = crate::package_name::PackageName::parse("p").expect("valid name");
        index::Sha256Hex::parse(&package, &fill.repeat(64)).expect("valid digest")
    }

    /// An entry version recording `sha256` and `capabilities`.
    #[allow(clippy::expect_used)] // test fixture: every literal is valid
    fn entry(sha256: index::Sha256Hex, capabilities: BTreeSet<Capability>) -> index::EntryVersion {
        let package = crate::package_name::PackageName::parse("p").expect("valid name");
        index::EntryVersion {
            version: crate::published_version::PublishedVersion::parse("0.1.0")
                .expect("valid version"),
            source: index::SourceUrl::parse(&package, "https://github.com/example/p")
                .expect("valid source url"),
            rev: index::PinnedRev::from_full_sha(
                &package,
                "9f2c7b1e0a4d5c6f8b2a1e3d4c5b6a7f8e9d0c1b",
            )
            .expect("valid pinned rev"),
            sha256,
            capabilities,
            signature: None,
        }
    }

    /// An entry whose recorded digest is not the audited tree's is refused.
    #[test]
    fn admission_refuses_a_digest_other_than_the_audited_one() {
        let audited = audit::AuditedPackage::for_test(digest("a"), BTreeSet::new());
        assert!(
            admit_against_audit(&entry(digest("a"), BTreeSet::new()), "p", &audited).is_ok(),
            "control: the audited digest and set are admitted"
        );
        assert!(
            matches!(
                admit_against_audit(&entry(digest("b"), BTreeSet::new()), "p", &audited),
                Err(CliError::HashMismatch { .. })
            ),
            "a recorded digest other than the audited one is refused"
        );
    }

    /// An entry whose recorded capabilities are not the audited set is refused.
    #[test]
    fn admission_refuses_capabilities_other_than_the_audited_set() {
        let audited =
            audit::AuditedPackage::for_test(digest("a"), BTreeSet::from([Capability::Network]));
        assert!(
            admit_against_audit(
                &entry(digest("a"), BTreeSet::from([Capability::Network])),
                "p",
                &audited
            )
            .is_ok(),
            "control: the audited set is admitted"
        );
        assert!(
            matches!(
                admit_against_audit(&entry(digest("a"), BTreeSet::new()), "p", &audited),
                Err(CliError::PackageAudit(_))
            ),
            "an entry hiding an audited capability is refused"
        );
    }

    /// The desktop packager emits the webview app, titled by the manifest's
    /// `delivery.desktop` window, and never the served web app.
    #[test]
    fn desktop_packager_emits_webview() {
        const WEB_APP: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub

type Msg
    = Increment

type alias Model =
    { count : Int }

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model =
    ( { model | count = model.count + 1 }, Cmd.none )

view : Model -> Element Msg
view _model =
    Ui.el [ Ui.onClick Increment ] (Ui.text "+")

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

main =
    Web.tea
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        , routes = []
        , notFound = Increment
        }
"#;
        let tree = crate::project_root::SourceTree::main(WEB_APP)
            .field("delivery = { desktop = { title = \"Packaged\", width = 640, height = 480 } }");
        let fixture = crate::RootFixture::from_tree(&tree).expect("fixture");
        let manifest_path = fixture.manifest_path();
        let manifest = project::parse_manifest(&manifest_path).expect("manifest");
        let gated = BundleAssembler::gate_desktop(
            &manifest,
            &manifest_path,
            NativeFinish::Dev,
            fixture.path(),
        )
        .expect("a web app passes the desktop gate");
        let out = ipe_test_temp::temp_root()
            .join(format!("ipe-desktop-packager-emit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        gated
            .emit(OutTarget::Path(&out))
            .expect("the packaged app emits");
        // `ipe_main` sits in the entry's module file when the program has
        // more than one home, so the whole emitted program is read.
        let mut program = std::fs::read_to_string(out.join("src/main.rs")).expect("main.rs");
        if let Ok(mods) = std::fs::read_dir(out.join("src/ipe_mods")) {
            for entry in mods.flatten() {
                program.push_str(&std::fs::read_to_string(entry.path()).expect("module file"));
            }
        }
        let _ = std::fs::remove_dir_all(&out);
        assert!(
            program.contains("fn ipe_main() -> ipe_runtime::tea::WebViewApp"),
            "not the webview executor"
        );
        assert!(
            program.contains("title: \"Packaged\".to_string(), size: (640, 480)"),
            "not the manifest window"
        );
        assert!(
            !program.contains("ipe_runtime::tea::WebApp("),
            "the served web app was emitted"
        );
    }
}
