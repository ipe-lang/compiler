//! The runtime crate source, embedded in the `ipe` binary and materialized on
//! demand.
//!
//! A copied `ipe` binary must be able to build a program with nothing beside it
//! but a Rust toolchain — no separate runtime download, no version-mismatch
//! hazard. To make that true, the runtime crate SOURCE (`src/runtime/rust`: its
//! `Cargo.toml` + `src/**`) is compiled into this binary as a byte-tree and
//! written to `<IPE_HOME>/runtime/<version>/rust` the first time a build needs
//! it. Because the binary materializes its OWN embedded source, the runtime the
//! emitted project links against matches the compiler that emitted it by
//! construction — there is no cross-machine version to drift.
//!
//! Only SOURCE is embedded; it is compiled locally by the user's toolchain. No
//! prebuilt object code ships (that would be an ABI/trust surface, not a source
//! distribution).
//!
//! # `IPE_HOME`
//! The materialized runtime lives under `IPE_HOME`, resolved once:
//! 1. `$IPE_HOME` — explicit override; refused unless absolute.
//! 2. `$XDG_DATA_HOME/ipe` — the XDG data root, when absolute.
//! 3. `$HOME/.ipe` — the default, when `HOME` is absolute.
//!
//! Nothing is ever written outside the resolved `IPE_HOME`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use include_dir::{Dir, include_dir};

use crate::CliError;

/// The runtime crate source tree, embedded at build time from the workspace
/// `src/runtime/rust` directory (the crate ROOT, so the materialized tree is a
/// self-contained buildable crate). `tests/` is present in the source tree but
/// is not needed to build the crate as a path dependency; it is skipped on
/// materialize (see [`materialize`]) so the on-disk runtime is the minimal
/// buildable crate.
static RUNTIME_CRATE: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/../runtime/rust");

/// The compiler's own version — the workspace-synced `version` field.
///
/// The embedded runtime crate is materialized WITH this version (see
/// [`concretize_manifest`]), so the on-disk runtime version equals the compiler
/// version by construction.
pub const COMPILER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The runtime crate's package name.
///
/// This is the single token that identifies a directory as a valid runtime crate
/// root. A candidate whose `Cargo.toml` does not declare this package is rejected
/// — never walked past to a wrong runtime.
pub const RUNTIME_PACKAGE: &str = "ipe-runtime-rust";

/// A resolved, verified runtime crate root: the directory holding the runtime
/// `Cargo.toml` an emitted project names as its path dependency, paired with the
/// version that root declares.
///
/// The only way to obtain one is through [`resolve`], which constructs it solely
/// from a candidate that has been checked to hold a `Cargo.toml` declaring the
/// [`RUNTIME_PACKAGE`]. An empty, half-present, or wrong-package directory can
/// never be represented as a `ResolvedRuntime` — a wrong runtime is
/// unrepresentable, not merely unlikely.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedRuntime {
    root: PathBuf,
    version: String,
}

impl ResolvedRuntime {
    /// The verified, absolute crate root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The version the resolved crate's `Cargo.toml` declares.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }
}

/// The relative path, from a runtime crate root, of the manifest.
const MANIFEST: &str = "Cargo.toml";

/// The `version.workspace = true` line the embedded manifest carries (it inherits
/// the version from the workspace at build time). A standalone materialized crate
/// has no parent workspace, so this line is rewritten to a concrete version.
const WORKSPACE_VERSION_LINE: &str = "version.workspace = true";

/// Read a candidate crate root's manifest and return its declared version iff the
/// manifest declares the runtime package. `None` means "not a runtime crate
/// root" — the caller treats that as a hard refusal, never a walk-on.
fn runtime_version_at(root: &Path) -> Option<String> {
    let text = crate::io_bounded::read_to_string_capped(
        &root.join(MANIFEST),
        crate::io_bounded::SMALL_FILE_READ_CAP,
    )
    .ok()?;
    let declares_package = text
        .lines()
        .any(|l| l.trim() == format!("name = \"{RUNTIME_PACKAGE}\""));
    if !declares_package {
        return None;
    }
    // A materialized crate carries a concrete `version = "…"`; an in-repo crate
    // inherits it via `version.workspace = true`. In-repo, the version is the
    // compiler's own (both are the workspace version), so report that.
    let concrete = text.lines().find_map(|l| {
        let l = l.trim();
        l.strip_prefix("version = \"")
            .and_then(|rest| rest.strip_suffix('"'))
            .map(str::to_owned)
    });
    Some(concrete.unwrap_or_else(|| COMPILER_VERSION.to_owned()))
}

/// Verify that `root` is a runtime crate root and, if so, canonicalize it into a
/// [`ResolvedRuntime`]. A non-runtime directory yields `Ok(None)`; the caller
/// decides whether that is a hard error (an explicit override) or a fall-through
/// (an in-repo probe).
fn verify(root: &Path) -> Result<Option<ResolvedRuntime>, CliError> {
    let Some(version) = runtime_version_at(root) else {
        return Ok(None);
    };
    let canonical = root.canonicalize().map_err(|e| CliError::Io {
        path: root.to_path_buf(),
        source: e,
    })?;
    Ok(Some(ResolvedRuntime {
        root: canonical,
        version,
    }))
}

/// Resolve `IPE_HOME` (see the module doc). The returned path is not created;
/// [`materialize`] creates it under the runtime subdirectory as needed.
///
/// # Errors
/// - [`CliError::EnvDirNotAbsolute`] when `IPE_HOME` is set but not absolute.
/// - [`CliError::RuntimeHomeUnknown`] when no override, no absolute
///   `XDG_DATA_HOME`, and no absolute home are set — there is no directory to
///   materialize into.
pub fn ipe_home() -> Result<PathBuf, CliError> {
    ipe_home_from(
        std::env::var_os("IPE_HOME"),
        std::env::var_os("XDG_DATA_HOME"),
        crate::env_dir::home(),
    )
}

/// Resolve `IPE_HOME` from the raw override, raw `XDG_DATA_HOME`, and the home.
fn ipe_home_from(
    ipe_home: Option<std::ffi::OsString>,
    xdg_data_home: Option<std::ffi::OsString>,
    home: Option<PathBuf>,
) -> Result<PathBuf, CliError> {
    if let Some(dir) = crate::env_dir::explicit_override("IPE_HOME", ipe_home)? {
        return Ok(dir);
    }
    crate::env_dir::absolute(xdg_data_home)
        .map(|xdg| xdg.join("ipe"))
        .or_else(|| home.map(|h| h.join(".ipe")))
        .ok_or(CliError::RuntimeHomeUnknown)
}

/// Rewrite the embedded manifest's `version.workspace = true` into a concrete
/// `version = "<COMPILER_VERSION>"`, so the materialized crate builds standalone
/// (it has no parent workspace to inherit from) AND declares exactly the
/// compiler's version. Every other line is preserved verbatim.
fn concretize_manifest(manifest: &str) -> String {
    manifest
        .lines()
        .map(|line| {
            if line.trim() == WORKSPACE_VERSION_LINE {
                format!("version = \"{COMPILER_VERSION}\"")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + if manifest.ends_with('\n') { "\n" } else { "" }
}

/// Prepare the runtime manifest for bundling alongside an emitted dep-model
/// crate: concretize the version AND strip every `[dev-dependencies]` /
/// `[target.*.dev-dependencies]` section.
///
/// Dev-dependency sections are irrelevant when the runtime crate is used as a
/// cargo dependency (cargo never installs dev deps for non-root crates). They
/// may however contain workspace-relative `path` entries (e.g. sibling compiler
/// crates) that do not resolve when the manifest lives outside the workspace.
/// Stripping them keeps the bundled crate's manifest self-contained.
///
/// The strip is line-granular: a `[…dev-dependencies]` header line begins a
/// section that continues until the next TOML table header (`[` at column 0)
/// or end of file. Comment lines inside a skipped section are dropped with the
/// section, keeping the output clean.
fn prepare_bundled_manifest(manifest: &str) -> String {
    let concretized = concretize_manifest(manifest);
    let mut out = String::with_capacity(concretized.len());
    let mut in_dev_deps = false;
    let trailing_newline = concretized.ends_with('\n');
    for line in concretized.lines() {
        let trimmed = line.trim();
        // A TOML table header at column 0 starts a new section.
        if trimmed.starts_with('[') {
            in_dev_deps = trimmed.contains("dev-dependencies");
        }
        if !in_dev_deps {
            out.push_str(line);
            out.push('\n');
        }
    }
    // Preserve (or not) the trailing newline the original carried.
    if !trailing_newline && out.ends_with('\n') {
        out.pop();
    }
    out
}

/// Collect the embedded runtime crate as a path→text map for dep bundling.
///
/// Rewrites the root `Cargo.toml` via [`prepare_bundled_manifest`] (concrete
/// version, no dev-dependencies) and skips `tests/`. Relative paths are rooted
/// at the crate root (e.g. `Cargo.toml`, `src/mod.rs`).
///
/// Used to materialise `ipe_runtime_dep/` alongside a dep-model emitted crate
/// so the relative path dep in its `Cargo.toml` resolves in any environment.
///
/// # Errors
///
/// [`CliError::RuntimeMaterializeFailed`] when an embedded file is not valid
/// UTF-8 (unexpected for in-repo source; surfaced loudly rather than silently
/// skipped).
pub fn collect_embedded_crate_text()
-> Result<&'static std::collections::BTreeMap<std::path::PathBuf, String>, CliError> {
    // The embedded runtime crate is compiled-in (`include_dir!`) and thus
    // invariant for the process lifetime, as is the pure manifest transform
    // applied to it. Compute the path→text map once and reuse it across every
    // emit cycle rather than re-walking + re-validating the tree each time. On
    // the UTF-8 refusal path the detail is cached so the fail-closed error
    // still surfaces (once, at first use, deterministically).
    static EMBEDDED: LazyLock<Result<BTreeMap<PathBuf, String>, String>> = LazyLock::new(|| {
        let mut out = BTreeMap::new();
        collect_dir_text_from_embedded(&RUNTIME_CRATE, Path::new(""), true, &mut out).map_err(
            |e| match e {
                CliError::RuntimeMaterializeFailed { detail } => detail,
                other => other.to_string(),
            },
        )?;
        Ok(out)
    });
    EMBEDDED
        .as_ref()
        .map_err(|detail| CliError::RuntimeMaterializeFailed {
            detail: detail.clone(),
        })
}

/// Recursive helper for [`collect_embedded_crate_text`]: traverses `dir`,
/// prepending `prefix` to each entry's relative path.
fn collect_dir_text_from_embedded(
    dir: &include_dir::Dir<'_>,
    prefix: &std::path::Path,
    at_root: bool,
    out: &mut std::collections::BTreeMap<std::path::PathBuf, String>,
) -> Result<(), CliError> {
    for entry in dir.entries() {
        match entry {
            include_dir::DirEntry::Dir(sub) => {
                let name = sub.path().file_name().unwrap_or_default();
                if at_root && name == std::ffi::OsStr::new("tests") {
                    continue;
                }
                collect_dir_text_from_embedded(sub, &prefix.join(name), false, out)?;
            }
            include_dir::DirEntry::File(file) => {
                let name = file.path().file_name().unwrap_or_default();
                let rel = prefix.join(name);
                let text = std::str::from_utf8(file.contents()).map_err(|_| {
                    CliError::RuntimeMaterializeFailed {
                        detail: format!(
                            "embedded runtime file {} is not valid UTF-8",
                            rel.display()
                        ),
                    }
                })?;
                let text = if at_root && name == std::ffi::OsStr::new(MANIFEST) {
                    prepare_bundled_manifest(text)
                } else {
                    text.to_owned()
                };
                out.insert(rel, text);
            }
        }
    }
    Ok(())
}

/// Write the embedded crate tree under `dest` (a fresh directory), rewriting the
/// root manifest's version and skipping the `tests/` subtree. Fails closed on the
/// first filesystem error — a partially written tree under `dest` is a temp dir
/// the caller discards, never the live runtime.
fn write_tree(dir: &Dir<'_>, dest: &Path, at_root: bool) -> Result<(), CliError> {
    std::fs::create_dir_all(dest).map_err(|e| CliError::Io {
        path: dest.to_path_buf(),
        source: e,
    })?;
    for entry in dir.entries() {
        match entry {
            include_dir::DirEntry::Dir(sub) => {
                let name = sub.path().file_name().unwrap_or_default();
                // `tests/` is not part of the buildable dependency and carries a
                // nested proof crate; skip it so the on-disk runtime is minimal.
                if at_root && name == std::ffi::OsStr::new("tests") {
                    continue;
                }
                write_tree(sub, &dest.join(name), false)?;
            }
            include_dir::DirEntry::File(file) => {
                let name = file.path().file_name().unwrap_or_default();
                let target = dest.join(name);
                if at_root && name == std::ffi::OsStr::new(MANIFEST) {
                    let text = std::str::from_utf8(file.contents()).map_err(|_| {
                        CliError::RuntimeMaterializeFailed {
                            detail: "embedded runtime manifest is not valid UTF-8".to_owned(),
                        }
                    })?;
                    std::fs::write(&target, concretize_manifest(text)).map_err(|e| {
                        CliError::Io {
                            path: target,
                            source: e,
                        }
                    })?;
                } else {
                    std::fs::write(&target, file.contents()).map_err(|e| CliError::Io {
                        path: target,
                        source: e,
                    })?;
                }
            }
        }
    }
    Ok(())
}

/// Materialize the embedded runtime source to `<IPE_HOME>/runtime/<version>/rust`
/// and return the verified root.
///
/// Atomic: the whole tree is written to a sibling temp directory under the same
/// `runtime/` parent, then renamed into place — a build never sees a
/// half-written runtime. Idempotent: if `<version>/rust` already exists and
/// verifies as a runtime crate root, the write is skipped (the fast path). Every
/// path is under `IPE_HOME`; nothing is written elsewhere.
///
/// # Errors
/// - [`CliError::RuntimeHomeUnknown`] if no `IPE_HOME` can be resolved.
/// - [`CliError::Io`] / [`CliError::RuntimeMaterializeFailed`] on any filesystem
///   failure — a disk-full or permission error is a loud, fail-closed refusal,
///   never a wrong or empty runtime.
pub fn materialize() -> Result<ResolvedRuntime, CliError> {
    let home = ipe_home()?;
    let runtime_parent = home.join("runtime");
    let version_dir = runtime_parent.join(COMPILER_VERSION);
    let final_root = version_dir.join("rust");

    // Fast path: an already-materialized, valid runtime for this version.
    if let Some(resolved) = verify(&final_root)? {
        return Ok(resolved);
    }

    std::fs::create_dir_all(&runtime_parent).map_err(|e| CliError::Io {
        path: runtime_parent.clone(),
        source: e,
    })?;

    // Stage the whole `<version>` directory in a sibling temp, then rename it
    // into place: the observable `<version>/rust` appears atomically and fully
    // formed. The temp name carries the pid so concurrent `ipe` processes do not
    // collide on the staging directory.
    let staging = runtime_parent.join(format!(
        ".staging-{COMPILER_VERSION}-{}",
        std::process::id()
    ));
    // A leftover staging dir from a crashed prior run would poison the write; the
    // remove is best-effort and only ever touches our own staging path.
    let _ = std::fs::remove_dir_all(&staging);
    let staged_root = staging.join("rust");

    let write_result = write_tree(&RUNTIME_CRATE, &staged_root, true);
    if let Err(e) = write_result {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(e);
    }

    // Verify the staged tree BEFORE it becomes the live runtime — a staged tree
    // that does not verify is a bug in the embed, surfaced loudly here.
    let staged_ok = verify(&staged_root)?.is_some();
    if !staged_ok {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(CliError::RuntimeMaterializeFailed {
            detail: "the staged runtime tree did not verify as a runtime crate root".to_owned(),
        });
    }

    // Rename the staged `<version>` into place. If a concurrent process won the
    // race and created `<version>` first, treat an existing valid target as
    // success (idempotent) and discard our staging copy.
    if std::fs::rename(&staging, &version_dir).is_err() {
        let _ = std::fs::remove_dir_all(&staging);
        if verify(&final_root)?.is_none() {
            return Err(CliError::RuntimeMaterializeFailed {
                detail: format!("could not place the runtime at {}", version_dir.display()),
            });
        }
    }

    verify(&final_root)?.ok_or_else(|| CliError::RuntimeMaterializeFailed {
        detail: format!(
            "materialized runtime at {} did not verify",
            final_root.display()
        ),
    })
}

/// Resolve the runtime crate root for the dependency-model emit. The resolution
/// chain, in order:
///
/// 1. `$IPE_RUNTIME_DIR` — an explicit override (dev / advanced). It may name the
///    runtime crate root (`Cargo.toml` declaring [`RUNTIME_PACKAGE`]) or any path
///    inside it (e.g. the historical `…/rust/src` source-tree location); the crate
///    root is found by walking up. A path with no runtime crate root at or above
///    it is a loud error.
/// 2. In-repo `src/runtime/rust` — an upward walk from the current directory, so
///    a repository checkout builds against the live source (dev workflow and
///    goldens unchanged).
/// 3. Otherwise materialize the embedded source to `<IPE_HOME>/runtime/<version>/rust`
///    and use that (the normal installed path).
///
/// Whichever branch resolves, the result must declare the compiler's own
/// version: emitting against a differently-versioned runtime is unrepresentable,
/// so a stale override or drifted in-repo crate is refused here rather than
/// linked into a `cargo` build that fails opaquely.
///
/// # Errors
/// - [`CliError::RuntimeDirInvalid`] when `$IPE_RUNTIME_DIR` is set but has no
///   runtime crate root at or above it.
/// - [`CliError::RuntimeVersionMismatch`] when the resolved runtime's declared
///   version is not the compiler's.
/// - Any error from [`materialize`] when the embedded fallback is taken.
pub fn resolve() -> Result<ResolvedRuntime, CliError> {
    let resolved = if let Some(dir) = std::env::var_os("IPE_RUNTIME_DIR") {
        resolve_override(&PathBuf::from(dir))?
    } else if let Some(in_repo) = resolve_in_repo()? {
        in_repo
    } else {
        materialize()?
    };
    check_version(resolved)
}

/// Refuse a resolved runtime whose declared version is not the compiler's own.
/// The emitted project pins features against the compiler's runtime, so linking
/// a differently-versioned crate fails deep inside `cargo`; this catches the
/// drift at resolution time and refuses loudly instead. A [`materialize`]d
/// runtime declares [`COMPILER_VERSION`] by construction and always passes; the
/// guard bites a stale `IPE_RUNTIME_DIR` override or an in-repo crate whose
/// manifest has drifted.
fn check_version(resolved: ResolvedRuntime) -> Result<ResolvedRuntime, CliError> {
    if resolved.version() == COMPILER_VERSION {
        Ok(resolved)
    } else {
        Err(CliError::RuntimeVersionMismatch {
            path: resolved.root().to_path_buf(),
            found: resolved.version().to_owned(),
            expected: COMPILER_VERSION.to_owned(),
        })
    }
}

/// Resolve the `$IPE_RUNTIME_DIR` override: verify it names a runtime crate root,
/// else a loud, typed refusal (with a targeted hint when it points at the inner
/// module directory).
fn resolve_override(path: &Path) -> Result<ResolvedRuntime, CliError> {
    // Accept the crate root directly, or any path inside the crate — the
    // historical source-tree locations (`…/rust/src`, `…/src/ipe_runtime`) — by
    // walking up to the crate root that holds `Cargo.toml`. This keeps every
    // existing `IPE_RUNTIME_DIR` setting working across the meaning change from
    // "source tree" to "crate root".
    let mut here: Option<&Path> = Some(path);
    while let Some(dir) = here {
        if let Some(resolved) = verify(dir)? {
            return Ok(resolved);
        }
        here = dir.parent();
    }
    // Nothing at or above the given path names a runtime crate root.
    let points_at_inner = path.file_name() == Some(std::ffi::OsStr::new("ipe_runtime"))
        || path.ends_with("rust/src")
        || path.ends_with("runtime/rust/src");
    Err(CliError::RuntimeDirInvalid {
        path: path.to_path_buf(),
        points_at_inner,
    })
}

/// Upward walk from the current directory for the in-repo `src/runtime/rust`
/// crate root. `Ok(None)` means no in-repo runtime is above the current
/// directory (the normal case for an installed binary run outside a checkout).
fn resolve_in_repo() -> Result<Option<ResolvedRuntime>, CliError> {
    let cwd = std::env::current_dir().map_err(|e| CliError::Io {
        path: PathBuf::from("."),
        source: e,
    })?;
    let mut here: Option<&Path> = Some(cwd.as_path());
    while let Some(dir) = here {
        let candidate = dir.join("src").join("runtime").join("rust");
        if let Some(resolved) = verify(&candidate)? {
            return Ok(Some(resolved));
        }
        here = dir.parent();
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The embedded runtime crate's declared version equals the compiler
    /// version. This is the version guarantee: the binary materializes its own
    /// embedded source, and that source names the compiler's version, so an
    /// emitted project can never link a mismatched runtime (barring the explicit
    /// `IPE_RUNTIME_DIR` override).
    #[test]
    fn embedded_runtime_version_matches_compiler() {
        let manifest = RUNTIME_CRATE
            .get_file("Cargo.toml")
            .expect("embedded runtime crate must carry a Cargo.toml");
        let text = std::str::from_utf8(manifest.contents()).expect("embedded manifest is UTF-8");
        // The in-repo manifest inherits the version from the workspace; the
        // concretized form names it literally. Either way the effective version
        // is the compiler's.
        assert!(
            text.contains(WORKSPACE_VERSION_LINE),
            "embedded runtime manifest must inherit the workspace version"
        );
        let concretized = concretize_manifest(text);
        assert!(
            concretized.contains(&format!("version = \"{COMPILER_VERSION}\"")),
            "concretized runtime manifest must declare the compiler version {COMPILER_VERSION}"
        );
        assert!(
            !concretized.contains(WORKSPACE_VERSION_LINE),
            "concretized manifest must not keep the workspace-inherit line"
        );
    }

    /// The embedded tree declares the runtime package — a materialize would
    /// verify.
    #[test]
    fn embedded_runtime_declares_package() {
        let manifest = RUNTIME_CRATE
            .get_file("Cargo.toml")
            .expect("embedded runtime crate must carry a Cargo.toml");
        let text = std::str::from_utf8(manifest.contents()).unwrap();
        assert!(
            text.lines()
                .any(|l| l.trim() == format!("name = \"{RUNTIME_PACKAGE}\""))
        );
    }

    /// A resolved runtime whose manifest declares a version other than the
    /// compiler's is refused by [`check_version`] with the typed
    /// [`CliError::RuntimeVersionMismatch`], naming the resolved path and both
    /// versions. This is the guard that keeps a stale runtime from being emitted
    /// against.
    #[test]
    fn mismatched_runtime_version_is_rejected() {
        let sd = crate::scratch::ScratchDir::new("ipe-runtime-version-test").expect("scratch dir");
        let dir = sd.path().to_path_buf();
        std::mem::forget(sd); // caller's explicit remove_dir_all handles cleanup
        let bogus = "0.0.0-stale";
        assert_ne!(bogus, COMPILER_VERSION, "the test version must differ");
        std::fs::write(
            dir.join(MANIFEST),
            format!("[package]\nname = \"{RUNTIME_PACKAGE}\"\nversion = \"{bogus}\"\n"),
        )
        .expect("write bogus manifest");

        let resolved = verify(&dir)
            .expect("verify does not error on a well-formed manifest")
            .expect("a manifest declaring the package verifies");
        assert_eq!(resolved.version(), bogus);

        let err = check_version(resolved).expect_err("a mismatched version must be rejected");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            matches!(
                &err,
                CliError::RuntimeVersionMismatch { found, expected, path }
                    if found == bogus
                        && expected == COMPILER_VERSION
                        && path.ends_with(dir.file_name().expect("temp dir has a name"))
            ),
            "expected a RuntimeVersionMismatch naming {bogus} vs {COMPILER_VERSION}, got {err:?}"
        );
    }

    /// A resolved runtime declaring the compiler's own version passes
    /// [`check_version`] unchanged — the materialized path is exactly this case.
    #[test]
    fn matching_runtime_version_is_accepted() {
        let sd = crate::scratch::ScratchDir::new("ipe-runtime-version-ok").expect("scratch dir");
        let dir = sd.path().to_path_buf();
        std::mem::forget(sd); // caller's explicit remove_dir_all handles cleanup
        std::fs::write(
            dir.join(MANIFEST),
            format!("[package]\nname = \"{RUNTIME_PACKAGE}\"\nversion = \"{COMPILER_VERSION}\"\n"),
        )
        .expect("write matching manifest");
        let resolved = verify(&dir).expect("verify ok").expect("verifies");
        assert!(check_version(resolved).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `concretize_manifest` touches only the version line and preserves the rest
    /// verbatim (including a trailing newline).
    #[test]
    fn concretize_preserves_other_lines() {
        let input = "[package]\nname = \"ipe-runtime-rust\"\nversion.workspace = true\nedition = \"2024\"\n";
        let out = concretize_manifest(input);
        assert_eq!(
            out,
            format!(
                "[package]\nname = \"ipe-runtime-rust\"\nversion = \"{COMPILER_VERSION}\"\nedition = \"2024\"\n"
            )
        );
    }

    #[test]
    fn ipe_home_uses_an_absolute_override() {
        let got = ipe_home_from(
            Some("/opt/ipe".into()),
            Some("/xdg".into()),
            Some("/home/u".into()),
        );
        assert!(matches!(got, Ok(p) if p == std::path::Path::new("/opt/ipe")));
    }

    #[test]
    fn ipe_home_refuses_a_relative_or_empty_override() {
        for raw in ["", "ipe", "./ipe"] {
            let got = ipe_home_from(Some(raw.into()), None, Some("/home/u".into()));
            assert!(
                matches!(got, Err(CliError::EnvDirNotAbsolute { var: "IPE_HOME" })),
                "IPE_HOME={raw:?} must be refused: {got:?}"
            );
        }
    }

    #[test]
    fn ipe_home_skips_a_relative_xdg_data_home() {
        let got = ipe_home_from(None, Some("rel".into()), Some("/home/u".into()));
        assert!(matches!(got, Ok(p) if p == std::path::Path::new("/home/u/.ipe")));
        let got = ipe_home_from(None, Some("/xdg".into()), Some("/home/u".into()));
        assert!(matches!(got, Ok(p) if p == std::path::Path::new("/xdg/ipe")));
    }

    #[test]
    fn ipe_home_refuses_without_any_absolute_home() {
        let got = ipe_home_from(None, Some("rel".into()), None);
        assert!(matches!(got, Err(CliError::RuntimeHomeUnknown)));
    }
}
