//! Desktop packaging (`ipe build|release web desktop`): the Linux tarball is
//! materialised end-to-end on this box from a real compiled binary, and the
//! per-OS layout / macOS `Info.plist` content is asserted as pure data.
//!
//! The end-to-end Linux build is gated on `IPE_E2E=1` (it runs a real `cargo
//! build`); without it, that test returns early so the default `cargo test`
//! stays fast. The pure-data layout/plist assertions always run.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ipe::pack::desktop::{
    self, AppShape, BundleContent, BundleIdentity, DesktopOs, DesktopRefusal,
};
use ipe_ir::{Capability, WebCapability};

/// A trivial program whose compiled binary the E2E materialises into a Linux
/// bundle. The packager's deliverable is the bundle *around* a binary — laying
/// out the tree, copying the executable, writing the `.desktop` launcher and the
/// runtime note — which this exercises with a real, quickly-built binary rather
/// than paying for the system-webkit link the bundle content does not depend on.
const TRIVIAL_MAIN: &str = r#"module Main exposing (main)

import Ipe.Io

main = Io.println "packaged"
"#;

fn accepts(items: &[Capability]) -> BTreeSet<Capability> {
    items.iter().copied().collect()
}

// ── Pure-data assertions (always run) ─────────────────────────────────────────

#[test]
fn linux_layout_is_a_runnable_tarball_shape() {
    let identity = BundleIdentity::new("Counter", Some("1.2.3"), None);
    let layout =
        desktop::layout(DesktopOs::Linux, &identity, &accepts(&[]), None).expect("linux layout");
    let paths: Vec<&str> = layout.files.iter().map(|f| f.rel_path.as_str()).collect();
    assert!(
        paths.contains(&"bin/counter"),
        "carries the binary: {paths:?}"
    );
    assert!(
        paths.contains(&"counter.desktop"),
        "carries a .desktop launcher: {paths:?}"
    );
    assert!(
        paths.iter().any(|p| p.ends_with("RUNTIME.txt")),
        "carries the WebKitGTK runtime note: {paths:?}"
    );
}

#[test]
fn mac_plist_permission_keys_come_only_from_the_derivation() {
    // An app accepting geolocation → the derived location usage key appears; an
    // app accepting nothing → no usage-description key at all. This is the SSOT
    // property: the desktop packager never hand-writes a permission.
    let identity = BundleIdentity::new("Counter", Some("1.2.3"), None);

    let with_geo = desktop::layout(
        DesktopOs::MacOs,
        &identity,
        &accepts(&[Capability::JsPort(WebCapability::Geolocation)]),
        None,
    )
    .expect("mac layout");
    let plist = plist_of(&with_geo);
    assert!(
        plist.contains("NSLocationWhenInUseUsageDescription"),
        "geolocation app carries the location usage key: {plist}"
    );

    let pure =
        desktop::layout(DesktopOs::MacOs, &identity, &accepts(&[]), None).expect("mac layout");
    assert!(
        !plist_of(&pure).contains("UsageDescription"),
        "a pure app declares no usage-description key"
    );
}

#[test]
fn a_non_webview_shape_is_refused() {
    let err = desktop::require_webview(AppShape::Terminal)
        .expect_err("a terminal app is not desktop-packageable");
    assert_eq!(err, DesktopRefusal::NotWebView { shape: "terminal" });
}

/// The rendered `Info.plist` text of a mac layout.
#[allow(clippy::expect_used)] // test helper: a missing plist IS the failure
fn plist_of(layout: &desktop::BundleLayout) -> String {
    layout
        .files
        .iter()
        .find_map(|file| match &file.content {
            BundleContent::Generated(text) if file.rel_path == "Contents/Info.plist" => {
                Some(text.clone())
            }
            _ => None,
        })
        .expect("mac layout has an Info.plist")
}

// ── Planted symlinks in an owned dist (always run) ───────────────────────────

/// Planted symlinks in an owned `dist/<os>` are refused.
///
/// Both a symlinked bundle root and a path through a planted directory link
/// are refused; the link targets survive intact.
#[cfg(unix)]
#[test]
fn materialise_refuses_planted_symlinks() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("pack_desktop_symlink_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let victim = dir.join("victim");
    std::fs::create_dir_all(&victim).expect("victim dir");
    std::fs::write(victim.join("keep.txt"), "keep").expect("victim file");
    let fake_binary = dir.join("fake-binary");
    std::fs::write(&fake_binary, "binary").expect("fake binary");

    let identity = BundleIdentity::new("counter", Some("1.2.3"), None);
    let layout =
        desktop::layout(DesktopOs::Linux, &identity, &accepts(&[]), None).expect("linux layout");

    // A symlinked bundle root: never removed through.
    let dist = claim_dist(&dir.join("dist-a"), &dir.join("app"));
    std::os::unix::fs::symlink(&victim, dist.path().join(&layout.root_name)).expect("link");
    let result = desktop::materialise(&layout, &fake_binary, None, &dist);
    assert!(
        matches!(result, Err(ipe::CliError::OutputRefused(_))),
        "a symlinked bundle root must be refused, got {result:?}"
    );
    assert!(
        victim.join("keep.txt").is_file(),
        "the link target survives"
    );

    // A symlinked directory inside the tree the bundle is rebuilt in: refused.
    let dist_b = claim_dist(&dir.join("dist-b"), &dir.join("app"));
    std::os::unix::fs::symlink(&victim, dist_b.path().join("elsewhere")).expect("link");
    let escaped = dist_b.path_to("elsewhere/keep.txt");
    assert!(
        matches!(escaped, Err(ipe::CliError::OutputRefused(_))),
        "a path through a planted directory link must be refused, got {escaped:?}"
    );
    assert_eq!(
        std::fs::read_to_string(victim.join("keep.txt"))
            .ok()
            .as_deref(),
        Some("keep")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Claim `dist` as an output root proven disjoint from the project at `project`.
#[allow(clippy::expect_used)] // test helper: a refused claim IS the failure
fn claim_dist(dist: &std::path::Path, project: &std::path::Path) -> ipe::output_dir::OwnedDir {
    std::fs::create_dir_all(project).expect("project dir");
    let root =
        ipe::output_dir::OutputRoot::at(dist, &ipe::output_dir::ProjectPaths::of_file(project))
            .expect("prove dist");
    root.claim().expect("claim dist")
}

// ── End-to-end Linux artifact (IPE_E2E=1) ─────────────────────────────────────

/// Compile a real binary, then materialise its Linux bundle and assert the
/// tarball is a runnable layout: the compiled binary is present and executable,
/// the `.desktop` launcher points at it, and the `WebKitGTK` runtime note is
/// carried.
///
/// This is the one fully-provable-here OS artifact — it proves the packager's
/// deliverable (the bundle around a binary) on this box.
#[test]
fn linux_bundle_is_materialised_end_to_end() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("pack_desktop_linux_e2e");
    let _ = std::fs::remove_dir_all(&dir);
    let src = dir.join("src");
    std::fs::create_dir_all(&src).expect("create project src dir");
    let entry = src.join("Main.ipe");
    std::fs::write(&entry, TRIVIAL_MAIN).expect("write Main.ipe");

    let out_dir = dir.join("out").join("rust");
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build(&entry, &out_dir, &runtime).expect("ipe build of the program");

    let exe = PathBuf::from(
        e2e_support::build_rust_binary("pack_desktop_linux", &out_dir)
            .expect("cargo build of the program"),
    );

    let identity = BundleIdentity::new("counter", Some("1.2.3"), None);
    let layout =
        desktop::layout(DesktopOs::Linux, &identity, &accepts(&[]), None).expect("linux layout");
    let dist = claim_dist(&dir.join("out").join("dist").join("linux"), &src);
    let bundle_root = desktop::materialise(&layout, &exe, None, &dist).expect("materialise");

    // The binary landed and is executable.
    let bin = bundle_root.join("bin").join("counter");
    assert!(
        bin.is_file(),
        "the packaged binary exists at {}",
        bin.display()
    );
    assert_is_executable(&bin);

    // The .desktop launcher points at the binary.
    let desktop_entry =
        std::fs::read_to_string(bundle_root.join("counter.desktop")).expect(".desktop launcher");
    assert!(desktop_entry.contains("Exec=bin/counter"));
    assert!(desktop_entry.contains("Type=Application"));

    // The runtime-dependency note is carried and names WebKitGTK.
    let note =
        std::fs::read_to_string(bundle_root.join("RUNTIME.txt")).expect("runtime note present");
    assert!(
        note.contains("WebKitGTK"),
        "runtime note names WebKitGTK: {note}"
    );

    // The packaged binary is a real, non-empty executable that runs: exit-0 on a
    // trivial program proves the materialised binary is intact and launchable.
    let meta = std::fs::metadata(&bin).expect("binary metadata");
    assert!(meta.len() > 0, "the packaged binary is non-empty");
    let status = std::process::Command::new(&bin)
        .status()
        .expect("run the packaged binary");
    assert!(status.success(), "the packaged binary runs and exits 0");
}

#[cfg(unix)]
#[allow(clippy::expect_used)] // test helper: unreadable metadata IS the failure
fn assert_is_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode();
    assert!(
        mode & 0o111 != 0,
        "the packaged binary is executable (mode {mode:o})"
    );
}

#[cfg(not(unix))]
fn assert_is_executable(_path: &Path) {}
