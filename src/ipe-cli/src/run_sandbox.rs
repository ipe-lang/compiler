//! The runtime capability sandbox around the release run.
//!
//! `ipe release` resolves the program's capability set (`inferred ∪ declared`),
//! lowers it to a [`SandboxProfile`], embeds that floor into the binary it
//! builds, and `ipe release run` execs the app inside the OS jail. An
//! undeclared effect the app attempts fails at the OS boundary; a declared one
//! works. `ipe dev` reaches none of this: it checks no capabilities.
//!
//! The jail is **scoped to native-bearing programs** (ADR 0004). Pure Ipê is
//! structurally bounded to its inferred capabilities — an unreachable effect is
//! absent from the binary — so it needs no runtime jail and runs directly. Only
//! a program that crosses into `Rust.` FFI ([`Capability::NativeFfi`]) has
//! effects inference cannot prove, and only that program is jailed. See
//! [`is_native_bearing`].
//!
//! A platform with no jail primitive refuses a native-bearing release run: there
//! is no unconfined fallback.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::Path;

use ipe_diagnostics::Diagnostic as SharedDiag;
use ipe_ir::Capability;
use ipe_sandbox::run_jail::{
    self, DatabaseAxis, FloorIntent, FloorRefusal, RunJailDefect, SandboxProfile,
};

use crate::CliError;
use crate::project::ProjectManifest;
use crate::scratch::ScratchDir;

/// Whether a program is *native-bearing*: it crosses into opaque `Rust.` FFI
/// code, so its true effect set cannot be proven from Ipê inference and an OS
/// jail is the only containment.
///
/// This reads the same [`Capability::NativeFfi`] the lowerer inserts on any
/// `Rust.` crossing — a compile-time fact of the inference pass, never a source
/// heuristic. [`Capability::FfiRaw`] (an author-asserted `Rust.Ffi.call`
/// crossing) is read too, fail-closed: the lowerer always pairs it with
/// `NativeFfi`, but a set carrying only the disclosure axis must still jail. A
/// pure Ipê program (neither, whatever else it infers) is structurally bounded
/// to its inferred capabilities and needs no runtime jail, so callers run it
/// directly (ADR 0004).
#[must_use]
pub fn is_native_bearing(union: &BTreeSet<Capability>) -> bool {
    union.contains(&Capability::NativeFfi) || union.contains(&Capability::FfiRaw)
}

/// The resolved capability sets for a program about to run.
pub struct ResolvedCapabilities {
    /// The Ipê-inferred set (over the reachable kernels).
    pub inferred: BTreeSet<Capability>,
    /// The manifest-declared set (empty for a single-file program).
    pub declared: BTreeSet<Capability>,
}

impl ResolvedCapabilities {
    /// The authoritative union — the set the jail is built from.
    #[must_use]
    pub fn union(&self) -> BTreeSet<Capability> {
        self.inferred.union(&self.declared).copied().collect()
    }
}

/// Lower a database driver to the concrete axis the profile needs.
///
/// Every project has a resolved driver (it defaults to `SQLite`), so this is
/// total — there is no "unknown driver" path at `ipe dev run` (the fail-closed
/// [`DatabaseAxis::NotApplicable`] path exists for callers that genuinely cannot
/// resolve one).
#[must_use]
pub const fn axis_for_driver(
    driver: ipe_backend_rust::DbDriver,
    has_database: bool,
) -> DatabaseAxis {
    if !has_database {
        return DatabaseAxis::NotApplicable;
    }
    match driver {
        // A file-backed store is a filesystem effect.
        ipe_backend_rust::DbDriver::Sqlite => DatabaseAxis::Filesystem,
        // A TCP-connected server is a network effect.
        ipe_backend_rust::DbDriver::Postgres => DatabaseAxis::Network,
    }
}

/// Build the [`SandboxProfile`] for a program from its resolved capabilities and
/// the project's database driver.
///
/// # Errors
///
/// [`CliError::Usage`] wrapping the [`RunJailDefect`] display when the
/// profile cannot be lowered (an unknown database driver — fail-closed).
pub fn build_profile(
    caps: &ResolvedCapabilities,
    driver: ipe_backend_rust::DbDriver,
) -> Result<SandboxProfile, CliError> {
    let union = caps.union();
    let has_database = union.contains(&Capability::Database);
    let axis = axis_for_driver(driver, has_database);
    // The env allowlist is empty in the first cut: the manifest declares the
    // `env` axis (on/off), not per-variable names. Fewer re-exported vars is
    // the tighter, fail-closed direction; per-name env is a tracked refinement.
    let env_allowlist: Vec<String> = Vec::new();
    run_jail::profile_from_capabilities(&caps.inferred, &caps.declared, axis, &env_allowlist)
        .map_err(|e| {
            let shared: SharedDiag = RunJailDefect::Profile(e).into();
            CliError::Pipeline {
                file: std::path::PathBuf::new(),
                src: String::new(),
                diag: Box::new(shared),
            }
        })
}

/// Exec `app` inside the jail, with no unconfined fallback of any kind.
///
/// The release run path: a platform with no jail primitive refuses. On success
/// this does not return (the process becomes the jailed app); the only value
/// it can produce is the refusal, so a caller has no unjailed branch to take.
#[must_use]
pub fn exec_jailed(
    profile: &SandboxProfile,
    scoped_tmp: &Path,
    working_tree: &Path,
    app: &Path,
    app_args: &[OsString],
) -> CliError {
    let wants_wall_clock = profile.limits.wall_secs.is_some();
    let defect = match run_jail::probe_run_jail_tools(wants_wall_clock) {
        Ok(tools) => {
            match run_jail::exec_in_run_jail(
                &tools,
                profile,
                scoped_tmp,
                working_tree,
                app,
                app_args,
            ) {
                Err(defect) => defect,
                Ok(never) => match never {},
            }
        }
        Err(defect) => defect,
    };
    defect_error(defect)
}

/// The typed refusal a jail defect renders as, through the shared diagnostic
/// renderer.
fn defect_error(defect: RunJailDefect) -> CliError {
    let shared: SharedDiag = defect.into();
    CliError::Pipeline {
        file: std::path::PathBuf::new(),
        src: String::new(),
        diag: Box::new(shared),
    }
}

/// Create the per-run scoped writable tempdir (the jail's only writable mount
/// when `filesystem` is absent).
///
/// The name carries 128 bits of OS entropy and is created exclusively
/// (`O_EXCL`-style, mode 0700) via [`ScratchDir`], so a pre-seeded symlink at a
/// predictable path cannot be followed into the jail's writable mount. The
/// returned guard removes the directory on drop; the caller keeps it alive
/// across the jail exec (which replaces the process on success).
///
/// # Errors
///
/// [`CliError::ScratchUnavailable`] when the directory cannot be created.
pub fn make_scoped_tmp() -> Result<ScratchDir, CliError> {
    ScratchDir::new("ipe-run").map_err(|source| CliError::ScratchUnavailable { source })
}

/// The Rust source of a `#[used]` static that embeds the capability floor into
/// the emitted binary's `.rodata`.
///
/// `ipe release run` scans this *passively off disk* (never by executing the binary) as
/// the authoritative floor a tampered `ipe.profile` cannot go below —
/// [`ipe_sandbox::run_jail::scan_capfloor`] finds it by its
/// [`ipe_sandbox::run_jail::CAPFLOOR_MARKER`] prefix. The floor lands in
/// `.rodata` (referenced from `fn main`) so it survives linker GC and `strip`.
///
/// `intent` records which pipeline built the binary, so `ipe release run`
/// can refuse a development build.
#[must_use]
pub fn capfloor_static_source(profile: &SandboxProfile, intent: FloorIntent) -> String {
    let mut line = profile.to_capfloor_line(intent);
    // A trailing newline TERMINATES the floor line inside `.rodata`. `scan_capfloor`
    // reads from the marker to the first NUL or newline; without an explicit
    // terminator the scanner would run on into whatever bytes the linker places
    // adjacent, either garbling the line (parse fails -> the floor reads as absent
    // -> a legitimate binary is spuriously refused) or letting an attacker-linked
    // adjacent static extend the single legitimate line with extra grants. The
    // emitted terminator makes the line self-delimiting regardless of `.rodata`
    // layout — the scanner stops here, before any neighbour.
    line.push('\n');
    let bytes = line.as_bytes();
    // A byte array literal so the section holds exactly the terminated floor line
    // (no rustc string-merging surprises).
    let mut arr = String::new();
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            arr.push_str(", ");
        }
        arr.push_str(&b.to_string());
    }
    // The floor lands in `.rodata` (an ALLOCATED section) rather than a custom
    // named section: an allocated section survives `strip` (the deploy artifact
    // builds release with `strip = true`), whereas a non-alloc custom section is
    // stripped away. `#[used]` + `#[no_mangle]` keep the linker from
    // garbage-collecting the never-read static. `ipe release run` finds the floor by
    // scanning the binary for the unique `ipe-capfloor` marker — see
    // `ipe_sandbox::run_jail::scan_capfloor`.
    format!(
        "\n// The runtime capability FLOOR, embedded read-only in `.rodata` so a\n\
         // tampered ipe.profile cannot request less isolation than this binary was\n\
         // built for. `ipe release run` scans this out of the binary WITHOUT running it.\n\
         // `.rodata` survives `strip`; a custom link-section would not.\n\
         #[used]\n\
         #[unsafe(no_mangle)]\n\
         pub static IPE_CAPABILITY_FLOOR: [u8; {}] = [{arr}];\n",
        bytes.len()
    )
}

/// Write the deployable enforcement artifacts into an emitted native project.
///
/// Two artifacts: the strictly-parsed `ipe.profile` next to the crate, and the
/// capability-floor static appended to the emitted `src/main.rs` (embedded in
/// the binary). The profile is a *convenience mirror* the launcher parses; the
/// authoritative floor is the embedded static. A profile weaker than the floor
/// is refused at launch (`ipe release run`), so tampering the mirror alone cannot
/// under-isolate. Only the release pipeline writes these artifacts, so the floor
/// is always a release floor; they are written before the build, so the binary
/// carries exactly this floor.
///
/// # Errors
///
/// [`CliError::OutputRefused`] when `crate_dir` was replaced since its claim or
/// holds a symlink on the way; [`CliError::Io`] on any filesystem failure;
/// [`CliError::Usage`] when the emitted `fn main` anchor is absent.
pub fn write_build_artifacts(
    crate_dir: &crate::output_dir::OwnedDir,
    profile: &SandboxProfile,
) -> Result<(), CliError> {
    crate_dir
        .path_to("ipe.profile")?
        .write(profile.to_profile_string().as_bytes())?;
    embed_floor(
        crate_dir,
        &capfloor_static_source(profile, FloorIntent::Release),
    )
}

/// Embed the development marker into an emitted `ipe dev` crate: a constant,
/// maximally isolated floor whose intent is [`FloorIntent::Development`].
///
/// A dev build infers no capabilities and writes no `ipe.profile`. The marker
/// makes a release reader refuse the binary as a development build
/// ([`FloorRefusal::NotRelease`], which names the remedy). It also closes the
/// self-attested grant: [`run_jail::scan_capfloor`] reads a binary as a
/// release build only when every floor line in it names release, so a
/// release-shaped line the program carries in its own data never stands alone.
///
/// # Errors
///
/// [`CliError::OutputRefused`] when `crate_dir` was replaced since its claim or
/// holds a symlink on the way; [`CliError::Io`] on any filesystem failure;
/// [`CliError::Usage`] when the emitted `fn main` anchor is absent.
pub fn write_dev_floor_marker(crate_dir: &crate::output_dir::OwnedDir) -> Result<(), CliError> {
    embed_floor(
        crate_dir,
        &capfloor_static_source(
            &SandboxProfile::maximally_isolated(),
            FloorIntent::Development,
        ),
    )
}

/// Append `floor_static` to the emitted `src/main.rs`, with a `black_box` read
/// of it at the top of `fn main`.
///
/// A mere `#[used]` static is garbage-collected by an aggressive linker like
/// `mold`, and `strip` removes unreferenced data; the read keeps the bytes in
/// `.rodata`, where `strip` cannot touch them and `ipe release run` scans them
/// out passively. Idempotent: any prior floor block and reference are replaced.
///
/// # Errors
///
/// [`CliError::OutputRefused`] when `crate_dir` was replaced since its claim or
/// holds a symlink on the way; [`CliError::Io`] on any filesystem failure;
/// [`CliError::Usage`] when the emitted `fn main` anchor is absent.
fn embed_floor(
    crate_dir: &crate::output_dir::OwnedDir,
    floor_static: &str,
) -> Result<(), CliError> {
    let main_rs = crate_dir.path_to(Path::new("src").join("main.rs"))?;
    let existing = crate::io_bounded::read_to_string_capped(
        &main_rs.path(),
        crate::io_bounded::SOURCE_READ_CAP,
    )?;
    let base = strip_capfloor_block(&existing);
    let referenced = inject_floor_reference(&base)?;
    let with_floor = format!("{referenced}{floor_static}");
    main_rs.write(with_floor.as_bytes())
}

/// Remove any previously-appended capfloor block AND its main-body reference, so
/// re-emitting is idempotent (both are delimited by unique markers).
fn strip_capfloor_block(src: &str) -> String {
    const BLOCK_MARKER: &str = "\n// The runtime capability FLOOR, embedded read-only";
    const REF_MARKER: &str = "    // Retain the embedded capability floor";
    let without_block = src
        .find(BLOCK_MARKER)
        .map_or_else(|| src.to_owned(), |i| src[..i].to_owned());
    // Drop the injected reference line (and its comment) if present.
    without_block
        .lines()
        .filter(|l| !l.starts_with(REF_MARKER) && !l.contains("IPE_CAPABILITY_FLOOR"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// The line the linker retains the floor by: a `black_box` read of the static at
/// the top of `fn main`. Marks the floor bytes as genuinely used so no linker GC
/// or `strip` removes them.
const FLOOR_REFERENCE: &str = "    // Retain the embedded capability floor (keeps it past linker GC + strip).\n    std::hint::black_box(&IPE_CAPABILITY_FLOOR);\n";

/// Inject the floor reference at the top of `fn main() {` in the emitted source.
///
/// # Errors
///
/// [`CliError::Usage`] if the `fn main` anchor is absent (the emitted
/// program shape has drifted — refuse rather than emit an unreferenced floor
/// that a linker would collect).
fn inject_floor_reference(src: &str) -> Result<String, CliError> {
    const ANCHOR: &str = "fn main() {\n";
    let idx = src
        .find(ANCHOR)
        .ok_or_else(|| CliError::Usage(crate::text::msg::run_main_anchor_absent()))?;
    let insert_at = idx + ANCHOR.len();
    let mut out = String::with_capacity(src.len() + FLOOR_REFERENCE.len());
    out.push_str(&src[..insert_at]);
    out.push_str(FLOOR_REFERENCE);
    out.push_str(&src[insert_at..]);
    Ok(out)
}

/// A deployed release app read once and verified against its `ipe.profile`.
///
/// Holds the exact bytes the floor scan judged, so the jailed exec runs those
/// bytes ([`exec_verified_jailed`]) rather than re-opening the path the scan
/// read.
pub struct VerifiedArtifact {
    profile: SandboxProfile,
    bytes: Vec<u8>,
    path: std::path::PathBuf,
}

impl std::fmt::Debug for VerifiedArtifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedArtifact")
            .field("profile", &self.profile)
            .field("path", &self.path)
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// Read and verify the deployed artifact's floor against its `ipe.profile`.
///
/// The authoritative floor is the binary's embedded `.rodata` capfloor line,
/// scanned passively (the binary is never executed) over bytes read once
/// under [`crate::io_bounded::RELEASE_APP_READ_CAP`].
///
/// # Errors
///
/// [`CliError::Usage`] on a missing/tampered profile or a profile weaker
/// than the embedded floor (both refuse-to-run); [`CliError::FileTooLarge`]
/// on a binary past the cap.
pub fn load_and_verify_artifact(
    profile_path: &Path,
    binary_path: &Path,
) -> Result<VerifiedArtifact, CliError> {
    verify_artifact_under(
        profile_path,
        binary_path,
        crate::io_bounded::RELEASE_APP_READ_CAP,
    )
}

/// [`load_and_verify_artifact`] with the binary read held under `binary_cap`
/// bytes (a planted oversized binary is [`CliError::FileTooLarge`], never
/// buffered whole).
fn verify_artifact_under(
    profile_path: &Path,
    binary_path: &Path,
    binary_cap: u64,
) -> Result<VerifiedArtifact, CliError> {
    // Parse the profile mirror strictly (parse-fail ⇒ refuse).
    let profile_text =
        crate::io_bounded::read_to_string_capped(profile_path, run_jail::PROFILE_READ_CAP)?;
    let profile = run_jail::parse_profile(&profile_text).map_err(|e| {
        CliError::Usage(crate::text::msg::run_profile_unparsable(
            &RunJailDefect::ProfileWeakerThanFloor.code().as_str(),
            &e,
        ))
    })?;

    // Read the authoritative floor from the binary's embedded `.rodata` bytes
    // (passively — the binary is NOT executed). The floor must be readable,
    // a release build's, and no narrower than the profile — the one check the
    // release wrapper applies too.
    let bytes = crate::io_bounded::read_bytes_capped(binary_path, binary_cap)?;
    if let Err(refusal) = run_jail::verify_release_floor(&profile, &bytes) {
        let code = RunJailDefect::ProfileWeakerThanFloor.code();
        return Err(CliError::Usage(match refusal {
            FloorRefusal::Unreadable => crate::text::msg::run_floor_unreadable(&code.as_str()),
            FloorRefusal::NotRelease => crate::text::msg::run_floor_not_release(&code.as_str()),
            FloorRefusal::ProfileWider => {
                crate::text::Message::relay(&RunJailDefect::ProfileWeakerThanFloor)
            }
        }));
    }
    Ok(VerifiedArtifact {
        profile,
        bytes,
        path: binary_path.to_path_buf(),
    })
}

/// Run a [`VerifiedArtifact`] inside the run jail. Returns only on failure.
///
/// Where the jail takes a sealed delivery (Linux, macOS) the app runs from
/// the verified bytes themselves, so a file swapped in at the path after the
/// scan is never what runs. Elsewhere the jail execs the path.
#[must_use]
pub fn exec_verified_jailed(
    artifact: &VerifiedArtifact,
    scoped_tmp: &Path,
    working_tree: &Path,
    app_args: &[OsString],
) -> CliError {
    #[cfg(any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos"
    ))]
    {
        let wants_wall_clock = artifact.profile.limits.wall_secs.is_some();
        let defect = match run_jail::probe_run_jail_tools(wants_wall_clock) {
            Ok(tools) => match run_jail::write_sealed_app_memfd(&artifact.bytes) {
                Ok(sealed) => match run_jail::exec_embedded_in_run_jail(
                    &tools,
                    &artifact.profile,
                    scoped_tmp,
                    working_tree,
                    &sealed,
                    app_args,
                ) {
                    Err(defect) => defect,
                    Ok(never) => match never {},
                },
                Err(defect) => defect,
            },
            Err(defect) => defect,
        };
        defect_error(defect)
    }
    #[cfg(not(any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos"
    )))]
    {
        exec_jailed(
            &artifact.profile,
            scoped_tmp,
            working_tree,
            &artifact.path,
            app_args,
        )
    }
}

/// Resolve the inferred and declared capability sets for a run, given the
/// project manifest (if any) and the resolved entry file used for single-file
/// inference.
///
/// For a manifest project the inferred set is the package-wide union (every
/// shipped module), matching the package-capability posture; the declared set
/// is the manifest's `[capabilities]`. For a single file there is no manifest,
/// so inference is over the entry alone and the declared set is empty.
///
/// # Errors
///
/// Propagates lowering / IO failures from capability inference.
pub fn resolve_for_run(
    manifest: Option<&ProjectManifest>,
    manifest_path: Option<&Path>,
    entry: &Path,
) -> Result<ResolvedCapabilities, CliError> {
    if let (Some(m), Some(mpath)) = (manifest, manifest_path) {
        // A manifest project: the package-wide inferred union + the manifest's
        // declared set.
        let inferred = crate::infer_package_capabilities(mpath)?;
        Ok(ResolvedCapabilities {
            inferred,
            declared: m.capabilities.clone(),
        })
    } else {
        // A single file: inference over the entry alone, no declared set. The
        // inference routes through the same served-widget-aware SSOT every other
        // capability-audit surface uses, so a constructed `customElement` handle
        // (whose JS the emitter serves) discloses `custom-element` here too,
        // whether or not a `CustomElement.node` mounts it.
        let graph = crate::build_source_graph(entry)?;
        let program = graph.run_attributed(entry, |db, root, file| {
            ipe_db::lower_program(db, root, file).clone()
        })?;
        let inferred = crate::capabilities_including_served_widgets(
            &graph.db,
            graph.source_root,
            graph.entry_file,
            &program,
        );
        Ok(ResolvedCapabilities {
            inferred,
            declared: BTreeSet::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(inferred: &[Capability], declared: &[Capability]) -> ResolvedCapabilities {
        ResolvedCapabilities {
            inferred: inferred.iter().copied().collect(),
            declared: declared.iter().copied().collect(),
        }
    }

    #[test]
    fn union_merges_inferred_and_declared() {
        let c = caps(&[Capability::Network], &[Capability::Filesystem]);
        let u = c.union();
        assert!(u.contains(&Capability::Network));
        assert!(u.contains(&Capability::Filesystem));
    }

    #[test]
    fn sqlite_driver_lowers_database_to_filesystem() {
        assert_eq!(
            axis_for_driver(ipe_backend_rust::DbDriver::Sqlite, true),
            DatabaseAxis::Filesystem
        );
    }

    #[test]
    fn postgres_driver_lowers_database_to_network() {
        assert_eq!(
            axis_for_driver(ipe_backend_rust::DbDriver::Postgres, true),
            DatabaseAxis::Network
        );
    }

    #[test]
    fn no_database_axis_is_not_applicable() {
        assert_eq!(
            axis_for_driver(ipe_backend_rust::DbDriver::Sqlite, false),
            DatabaseAxis::NotApplicable
        );
    }

    #[test]
    fn build_profile_grants_the_union() {
        let c = caps(&[Capability::Network], &[Capability::Subprocess]);
        let p = build_profile(&c, ipe_backend_rust::DbDriver::Sqlite).expect("profile");
        assert!(p.network);
        assert!(p.subprocess);
    }

    #[test]
    fn native_bearing_is_the_native_ffi_axis() {
        // A pure program with real (but structural) capabilities is NOT jailed.
        let pure: BTreeSet<Capability> =
            BTreeSet::from([Capability::Network, Capability::Filesystem]);
        assert!(!is_native_bearing(&pure));
        // Any `Rust.` crossing makes it native-bearing.
        let native: BTreeSet<Capability> = BTreeSet::from([Capability::NativeFfi]);
        assert!(is_native_bearing(&native));
        assert!(!is_native_bearing(&BTreeSet::new()));
    }

    #[test]
    fn floor_static_source_carries_the_capfloor_marker() {
        let p = SandboxProfile {
            network: true,
            ..SandboxProfile::maximally_isolated()
        };
        let src = capfloor_static_source(&p, FloorIntent::Release);
        // The floor LINE is encoded as byte values, not literal text — so assert
        // on the static shape and confirm the byte array decodes to the marker.
        assert!(src.contains("IPE_CAPABILITY_FLOOR"), "{src}");
        assert!(src.contains("#[used]"), "{src}");
        // The bytes are the exact `to_capfloor_line()` output.
        let line = p.to_capfloor_line(FloorIntent::Release);
        let first_byte = line.as_bytes().first().copied().unwrap_or(0).to_string();
        assert!(
            src.contains(&format!("[{first_byte}, ")),
            "byte array present: {src}"
        );
        assert!(line.contains("net=true"), "line grants network: {line}");
    }

    #[test]
    fn floor_static_terminates_the_line_with_a_newline() {
        let p = SandboxProfile {
            network: true,
            ..SandboxProfile::maximally_isolated()
        };
        let src = capfloor_static_source(&p, FloorIntent::Release);
        // The emitted byte array is exactly `to_capfloor_line()` + a terminating
        // newline, so the last array element is the newline's byte value (10).
        let line = p.to_capfloor_line(FloorIntent::Release);
        let len = line.len() + 1;
        assert!(
            src.contains(&format!("[u8; {len}]")),
            "the static holds the line plus one terminator byte: {src}"
        );
        assert!(
            src.contains(", 10];"),
            "the last emitted byte is a newline terminator: {src}"
        );
    }

    #[test]
    fn embedded_floor_line_is_self_delimiting_against_adjacent_rodata() {
        // The floor as it lands in `.rodata`: the terminated line the emitter
        // encodes, immediately followed by whatever the linker packs next.
        let profile = SandboxProfile {
            network: false,
            ..SandboxProfile::maximally_isolated()
        };
        let mut rodata = profile.to_capfloor_line(FloorIntent::Release).into_bytes();
        rodata.push(b'\n'); // the emitter's terminator
        // Adjacent bytes an attacker-linked static could place next — including a
        // second, more-permissive floor marker. The terminator must stop the scan
        // before any of it.
        rodata.extend_from_slice(b"ipe-capfloor 1 net=true fs=rw sub=true env=");

        let recovered = run_jail::scan_capfloor(&rodata)
            .expect("the terminated floor line is recovered from .rodata");
        // The recovered floor is the strict legitimate one — the trailing permissive
        // bytes did not extend it into a wider grant.
        assert!(
            !recovered.axes.network,
            "adjacent permissive bytes cannot raise the network ceiling"
        );
    }

    #[test]
    fn artifact_binary_read_is_capped_before_the_floor_scan() {
        let dir = ScratchDir::new("ipe-verify-cap").expect("scratch dir");
        let profile = SandboxProfile::maximally_isolated();
        let profile_path = dir.path().join("ipe.profile");
        std::fs::write(&profile_path, profile.to_profile_string()).expect("write profile");
        let mut binary = profile.to_capfloor_line(FloorIntent::Release).into_bytes();
        binary.push(b'\n');
        let binary_path = dir.path().join("ipe-app");
        std::fs::write(&binary_path, &binary).expect("write binary");
        let len = u64::try_from(binary.len()).expect("small length");

        // At the cap the floor is read and verified.
        assert!(
            verify_artifact_under(&profile_path, &binary_path, len).is_ok(),
            "a binary exactly at the cap verifies"
        );
        // One byte past the cap is refused before the binary is buffered whole.
        let over = verify_artifact_under(&profile_path, &binary_path, len - 1);
        assert!(
            matches!(over, Err(CliError::FileTooLarge { .. })),
            "a binary past the cap is FileTooLarge, got: {over:?}"
        );
    }

    #[test]
    fn inject_floor_reference_is_idempotent_under_strip_and_reinject() {
        // A minimal emitted-main shape.
        let base = "fn ipe_main() {}\n\nfn main() {\n    run();\n}\n";
        let profile = SandboxProfile::maximally_isolated();
        // First injection: reference inside main + static appended.
        let referenced = inject_floor_reference(base).expect("anchor present");
        let once = format!(
            "{referenced}{}",
            capfloor_static_source(&profile, FloorIntent::Release)
        );
        assert!(once.contains("black_box(&IPE_CAPABILITY_FLOOR)"));
        // Re-emitting: strip then re-inject must not stack a second block.
        let stripped = strip_capfloor_block(&once);
        assert!(
            !stripped.contains("IPE_CAPABILITY_FLOOR"),
            "strip removed the ref+static"
        );
        let re = inject_floor_reference(&stripped).expect("anchor present");
        let twice = format!(
            "{re}{}",
            capfloor_static_source(&profile, FloorIntent::Release)
        );
        assert_eq!(
            twice.matches("static IPE_CAPABILITY_FLOOR").count(),
            1,
            "exactly one floor static after re-emit"
        );
        assert_eq!(
            twice.matches("black_box(&IPE_CAPABILITY_FLOOR)").count(),
            1,
            "exactly one floor reference after re-emit"
        );
    }

    #[test]
    fn inject_floor_reference_refuses_a_missing_main_anchor() {
        assert!(inject_floor_reference("fn not_main() {}\n").is_err());
    }
}
