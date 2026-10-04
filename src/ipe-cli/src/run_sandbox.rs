//! Wiring the runtime capability sandbox around `ipe run`'s final exec.
//!
//! `ipe run` compiles, `cargo build`s, and then runs the emitted `ipe-app`
//! binary. This module inserts the jail between the build and the run for
//! programs that reach opaque native code: it resolves the program's capability
//! set (`inferred ∪ declared`), lowers it to a [`SandboxProfile`], establishes
//! the OS jail, and execs the app inside it. An undeclared effect the app
//! attempts fails at the OS boundary; a declared one works.
//!
//! The jail is **scoped to native-bearing programs** (ADR 0004). Pure Ipê is
//! structurally bounded to its inferred capabilities — an unreachable effect is
//! absent from the binary — so it needs no runtime jail and runs directly. Only
//! a program that crosses into `Rust.` FFI ([`Capability::NativeFfi`]) has
//! effects inference cannot prove, and only that program is jailed. See
//! [`is_native_bearing`].
//!
//! Where a native-bearing program runs on a platform with no jail primitive, the
//! jail cannot be established. That is fail-closed by default — the run refuses —
//! but [`OVERRIDE_ENV`] is the recorded-consent escape: with it set, the run
//! proceeds unconfined after a loud warning (ADR 0004 "best-effort with
//! consent"). Pure programs never take this path.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::Path;

use ipe_diagnostics::Diagnostic as SharedDiag;
use ipe_ir::Capability;
use ipe_sandbox::run_jail::{self, DatabaseAxis, RunJailDefect, SandboxProfile};

use crate::CliError;
use crate::project::ProjectManifest;
use crate::scratch::ScratchDir;

/// The narrow, run-jail-specific unsandboxed override — the recorded consent
/// that lets a native-bearing program run on a platform with no jail primitive.
///
/// DISTINCT from the FFI-compile override (`IPE_FFI_ALLOW_UNSANDBOXED`). Only a
/// native-bearing program can ever reach the jail (ADR 0004); when its platform
/// has no jail, this flag downgrades the fail-closed refusal to a loud warning
/// and proceeds unconfined. Unset, the run refuses. Never set it in CI.
pub const OVERRIDE_ENV: &str = "IPE_ALLOW_UNSANDBOXED";

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
/// total — there is no "unknown driver" path at `ipe run` (the fail-closed
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

/// Whether the resolved override env var is set to exactly `"1"` (mirroring the
/// build jail's strict `== "1"`, never a loose `is_some`).
#[must_use]
pub fn override_requested() -> bool {
    ipe_env::var_os(OVERRIDE_ENV).is_some_and(|v| v == "1")
}

/// Decide what to do when the jail cannot be established for a native-bearing
/// `union`.
///
/// Only native-bearing programs are jailed (ADR 0004), so this path is always
/// opaque native code on a platform with no jail primitive.
///
/// Fail-closed by default: without recorded consent ([`OVERRIDE_ENV`]) the run
/// refuses. With consent it prints a loud warning naming the axes that will run
/// unconfined and returns `Ok(true)` to proceed. There is no unconfined run of
/// native code without that explicit, recorded consent.
///
/// # Errors
///
/// [`CliError::Usage`] carrying the refusal (`IPE-F4413`) when consent is
/// absent.
pub fn resolve_refusal(
    defect: &RunJailDefect,
    union: &BTreeSet<Capability>,
) -> Result<bool, CliError> {
    // The axes that would run with the user's full authority (clock/random carry
    // no OS control, `unsafe` is a provenance label with no isolation surface, and
    // `custom-element` / `js-port` are browser-side disclosures the SERVER jail
    // never governs, so none of them is part of the jail-authority warning).
    let names: Vec<&str> = union
        .iter()
        .filter(|c| {
            !matches!(
                c,
                Capability::Clock
                    | Capability::Random
                    | Capability::Unsafe
                    | Capability::CustomElement
                    | Capability::JsPort(_)
            )
        })
        .map(|c| c.as_str())
        .collect();

    if !override_requested() {
        // Fail-closed: no jail here and no recorded consent. Route through the
        // shared typed renderer so F4413 gains the title-rule, snippet-less
        // band, help/remedy lines, and stable JSON schema.
        return Err(defect_error(defect.clone()));
    }

    // Recorded consent: warn loudly, in red, and proceed unconfined.
    // Route through the style palette so the warning honours use_color / NO_COLOR
    // and never leaks ANSI escapes into piped or redirected stderr.
    let mut screen = crate::screen::Screen::new(crate::screen::Stream::Stderr);
    let warning = override_warning(screen.palette(), &names.join(", "));
    screen.guttered(&warning).emit();
    Ok(true)
}

/// Establish the jail and exec `app` inside it, or apply the fail-closed
/// refusal / recorded-consent policy.
///
/// Callers invoke this only for native-bearing programs (ADR 0004). On success
/// (jail established) this **does not return** — it replaces the current process
/// with the jailed app. When the platform has no jail primitive and recorded
/// consent ([`OVERRIDE_ENV`]) is present, it returns `Ok(())` and the caller
/// performs the ordinary unjailed exec.
///
/// # Errors
///
/// [`CliError::Usage`] on any fail-closed refusal.
pub fn jail_and_exec(
    profile: &SandboxProfile,
    union: &BTreeSet<Capability>,
    scoped_tmp: &Path,
    working_tree: &Path,
    app: &Path,
    app_args: &[OsString],
) -> Result<(), CliError> {
    let wants_wall_clock = profile.limits.wall_secs.is_some();
    let tools = match run_jail::probe_run_jail_tools(wants_wall_clock) {
        Ok(t) => t,
        Err(defect) => {
            // The jail primitive is unavailable / platform unsupported: apply
            // the consent-or-refuse policy. If recorded consent lets the program
            // through, fall back to an unjailed run.
            return resolve_refusal(&defect, union).map(|_proceed_unconfined| ());
        }
    };
    match run_jail::exec_in_run_jail(&tools, profile, scoped_tmp, working_tree, app, app_args) {
        // `exec_in_run_jail` returns only on failure.
        Err(defect) => Err(defect_error(defect)),
        Ok(never) => match never {},
    }
}

/// Exec `app` inside the jail, with no unconfined fallback of any kind.
///
/// The release run path: the recorded-consent override ([`OVERRIDE_ENV`]) is
/// never consulted, so a platform with no jail primitive refuses. On success
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

/// Reconstruct the capability axes a profile grants, as a `Capability` set.
///
/// This is the input to the override/refusal policy for a deployed artifact
/// (which has no source to re-infer from). `database` is not reconstructed: it
/// was already lowered to `network`/`filesystem` when the profile was built, so
/// the axes here are the concrete OS-enforced ones.
#[must_use]
pub fn profile_axes(profile: &SandboxProfile) -> BTreeSet<Capability> {
    use ipe_sandbox::run_jail::FilesystemScope;
    let mut set = BTreeSet::new();
    if profile.network {
        set.insert(Capability::Network);
    }
    if matches!(profile.filesystem, FilesystemScope::WorkingTreeReadWrite) {
        set.insert(Capability::Filesystem);
    }
    if profile.subprocess {
        set.insert(Capability::Subprocess);
    }
    if !profile.env_allowlist.is_empty() {
        set.insert(Capability::Env);
    }
    set
}

/// The Rust source of a `#[used]` static that embeds the capability floor into
/// the emitted binary's `.rodata`.
///
/// `ipe exec` scans this *passively off disk* (never by executing the binary) as
/// the authoritative floor a tampered `ipe.profile` cannot go below —
/// [`ipe_sandbox::run_jail::scan_capfloor`] finds it by its
/// [`ipe_sandbox::run_jail::CAPFLOOR_MARKER`] prefix. The floor lands in
/// `.rodata` (referenced from `fn main`) so it survives linker GC and `strip`.
#[must_use]
pub fn capfloor_static_source(profile: &SandboxProfile) -> String {
    let mut line = profile.to_capfloor_line();
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
    // garbage-collecting the never-read static. `ipe exec` finds the floor by
    // scanning the binary for the unique `ipe-capfloor` marker — see
    // `ipe_sandbox::run_jail::scan_capfloor`.
    format!(
        "\n// The runtime capability FLOOR, embedded read-only in `.rodata` so a\n\
         // tampered ipe.profile cannot request less isolation than this binary was\n\
         // built for. `ipe exec` scans this out of the binary WITHOUT running it.\n\
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
/// is refused at launch (`ipe exec`), so tampering the mirror alone cannot
/// under-isolate.
///
/// # Errors
///
/// [`CliError::OutputRefused`] when `crate_dir` was replaced since its claim or
/// holds a symlink on the way; [`CliError::Io`] on any filesystem failure.
pub fn write_build_artifacts(
    crate_dir: &crate::output_dir::OwnedDir,
    profile: &SandboxProfile,
) -> Result<(), CliError> {
    // 1. The ipe.profile mirror.
    crate_dir
        .path_to("ipe.profile")?
        .write(profile.to_profile_string().as_bytes())?;

    // 2. Embed the capfloor into the emitted main.rs: a `#[used]` static holding
    //    the floor bytes, PLUS a `black_box` read of it at the top of `fn main`
    //    so the linker genuinely retains the bytes (a mere `#[used]` is
    //    garbage-collected by an aggressive linker like `mold`, and `strip`
    //    removes the unreferenced data). The read keeps the bytes in `.rodata`,
    //    where `strip` cannot touch them; `ipe exec` scans them out passively.
    //    Idempotent: a re-build replaces any prior floor block + reference.
    let main_rs = crate_dir.path_to(Path::new("src").join("main.rs"))?;
    let existing = crate::io_bounded::read_to_string_capped(
        &main_rs.path(),
        crate::io_bounded::SOURCE_READ_CAP,
    )?;
    let base = strip_capfloor_block(&existing);
    let referenced = inject_floor_reference(&base)?;
    let with_floor = format!("{referenced}{}", capfloor_static_source(profile));
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

/// Read and verify the deployed artifact's floor against its `ipe.profile`.
///
/// Returns the profile to jail with. The authoritative floor is the binary's
/// embedded `.rodata` capfloor line, scanned passively (the binary is never
/// executed).
///
/// # Errors
///
/// [`CliError::Usage`] on a missing/tampered profile or a profile weaker
/// than the embedded floor (both refuse-to-run).
pub fn load_and_verify_artifact(
    profile_path: &Path,
    binary_path: &Path,
) -> Result<SandboxProfile, CliError> {
    use ipe_sandbox::run_jail;

    // Parse the profile mirror strictly (parse-fail ⇒ refuse).
    let profile_text = crate::io_bounded::read_to_string_capped(
        profile_path,
        crate::io_bounded::SMALL_FILE_READ_CAP,
    )?;
    let profile = run_jail::parse_profile(&profile_text).map_err(|e| {
        CliError::Usage(crate::text::msg::run_profile_unparsable(
            &RunJailDefect::ProfileWeakerThanFloor.code().as_str(),
            &e,
        ))
    })?;

    // Read the authoritative floor from the binary's embedded `.rodata` bytes
    // (passively — the binary is NOT executed). A binary with no readable floor
    // refuses.
    let binary = std::fs::read(binary_path).map_err(|e| CliError::Io {
        path: binary_path.to_path_buf(),
        source: e,
    })?;
    let floor = run_jail::scan_capfloor(&binary).ok_or_else(|| {
        CliError::Usage(crate::text::msg::run_floor_unreadable(
            &RunJailDefect::ProfileWeakerThanFloor.code().as_str(),
        ))
    })?;

    // The profile MUST isolate at least as much as the embedded floor.
    if !profile.satisfies_capfloor(&floor) {
        return Err(CliError::Usage(crate::text::Message::relay(
            &RunJailDefect::ProfileWeakerThanFloor,
        )));
    }
    Ok(profile)
}

/// Build the sandbox-override warning string from a resolved palette.
///
/// Separating construction from emission makes the colour-gating contract
/// testable: callers drive this with `Palette::COLOR` or `Palette::PLAIN` and
/// assert on the presence or absence of ANSI escapes without touching a real
/// terminal.
fn override_warning(p: &crate::style::Palette, axes: &str) -> String {
    crate::style::sandbox_override_warning(p, OVERRIDE_ENV, axes)
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
    fn refusal_without_consent_carries_the_code_and_remediation() {
        let defect = RunJailDefect::PrimitiveUnavailable {
            missing: vec!["bwrap"],
        };
        // A native-bearing union — the only kind that reaches this path.
        let union: BTreeSet<Capability> =
            BTreeSet::from([Capability::NativeFfi, Capability::Network]);
        // No consent env set in this test process.
        let r = resolve_refusal(&defect, &union);
        assert!(r.is_err());
        let msg = format!("{}", r.unwrap_err());
        assert!(msg.contains("IPE-F4413"), "carries the defect code: {msg}");
        assert!(
            msg.contains(OVERRIDE_ENV),
            "names the consent escape: {msg}"
        );
        assert!(msg.contains("native"), "explains the native reason: {msg}");
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
        let src = capfloor_static_source(&p);
        // The floor LINE is encoded as byte values, not literal text — so assert
        // on the static shape and confirm the byte array decodes to the marker.
        assert!(src.contains("IPE_CAPABILITY_FLOOR"), "{src}");
        assert!(src.contains("#[used]"), "{src}");
        // The bytes are the exact `to_capfloor_line()` output.
        let line = p.to_capfloor_line();
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
        let src = capfloor_static_source(&p);
        // The emitted byte array is exactly `to_capfloor_line()` + a terminating
        // newline, so the last array element is the newline's byte value (10).
        let line = p.to_capfloor_line();
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
        let mut rodata = profile.to_capfloor_line().into_bytes();
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
            !recovered.network,
            "adjacent permissive bytes cannot raise the network ceiling"
        );
    }

    #[test]
    fn inject_floor_reference_is_idempotent_under_strip_and_reinject() {
        // A minimal emitted-main shape.
        let base = "fn ipe_main() {}\n\nfn main() {\n    run();\n}\n";
        let profile = SandboxProfile::maximally_isolated();
        // First injection: reference inside main + static appended.
        let referenced = inject_floor_reference(base).expect("anchor present");
        let once = format!("{referenced}{}", capfloor_static_source(&profile));
        assert!(once.contains("black_box(&IPE_CAPABILITY_FLOOR)"));
        // Re-emitting: strip then re-inject must not stack a second block.
        let stripped = strip_capfloor_block(&once);
        assert!(
            !stripped.contains("IPE_CAPABILITY_FLOOR"),
            "strip removed the ref+static"
        );
        let re = inject_floor_reference(&stripped).expect("anchor present");
        let twice = format!("{re}{}", capfloor_static_source(&profile));
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

    #[test]
    fn override_warning_plain_palette_has_no_ansi() {
        let w = override_warning(&crate::style::Palette::PLAIN, "network, filesystem");
        assert!(
            !w.contains('\x1b'),
            "plain palette must produce no ANSI escapes: {w:?}"
        );
        assert!(
            w.contains(OVERRIDE_ENV),
            "warning must name the override env var: {w:?}"
        );
        assert!(
            w.contains("network, filesystem"),
            "warning must list the axes: {w:?}"
        );
    }

    #[test]
    fn override_warning_colour_palette_has_red_and_bold() {
        let w = override_warning(&crate::style::Palette::COLOR, "network");
        assert!(
            w.contains('\x1b'),
            "colour palette must include ANSI escapes: {w:?}"
        );
        assert!(
            w.contains(crate::style::Palette::COLOR.red),
            "colour warning must be red: {w:?}"
        );
        assert!(
            w.contains(crate::style::Palette::COLOR.bold),
            "colour warning must be bold: {w:?}"
        );
        assert!(
            w.contains(crate::style::Palette::COLOR.reset),
            "colour warning must reset attributes: {w:?}"
        );
    }

    #[test]
    fn profile_axes_reconstructs_the_granted_set() {
        use ipe_sandbox::run_jail::FilesystemScope;
        let p = SandboxProfile {
            network: true,
            filesystem: FilesystemScope::WorkingTreeReadWrite,
            subprocess: false,
            env_allowlist: vec!["X".to_owned()],
            limits: ipe_sandbox::run_jail::RunResourceLimits::default(),
        };
        let axes = profile_axes(&p);
        assert!(axes.contains(&Capability::Network));
        assert!(axes.contains(&Capability::Filesystem));
        assert!(axes.contains(&Capability::Env));
        assert!(!axes.contains(&Capability::Subprocess));
    }
}
