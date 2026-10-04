//! Toolchain-free jailed deploy launcher.
//!
//! `ipe-wrapper` is the entry point of a release bundle produced by
//! `ipe release`. It locates `ipe-app` and `ipe.profile` by a FIXED RELATIVE
//! PATH next to the wrapper binary (no `cargo`/toolchain dependency), verifies
//! the profile against the capability floor embedded in `ipe-app`, and execs
//! the app inside the sandbox jail. Every verification failure is
//! fail-closed: the wrapper exits non-zero with a typed message to stderr —
//! it NEVER falls back to an unjailed or partially-verified run.
//!
//! ## Modes
//!
//! **Bundle mode** (default): the wrapper locates `ipe-app` and `ipe.profile`
//! as siblings at `../ipe-app` and `../ipe.profile` relative to the wrapper's
//! own path. The profile is a separately-auditable plain-text manifest.
//!
//! **Embed mode** (compiled with `IPE_EMBED_APP`/`IPE_EMBED_PROFILE` set at
//! build time, detected by the `embed_mode` cfg): the app binary and profile
//! are baked into the wrapper at compile time. `--show-profile` dumps the
//! embedded profile to stdout for auditability (the profile is never implicit).
//!
//! ## Honest limit
//!
//! The inner binary is a native ELF/Mach-O/PE executable. Nothing in this
//! crate prevents a sufficiently privileged operator from running it directly
//! without the wrapper. The wrapper makes the sanctioned, jailed, profile-
//! verified path the easy, toolchain-free one — not the only possible one.
//! This limit is documented; it is not a defect. The security guarantee is:
//! **any run through `ipe-wrapper` is jailed exactly as tightly as the
//! embedded floor requires**, and a tampered profile cannot weaken that.

#![forbid(unsafe_code)]

mod scratch;

use std::ffi::OsString;
use std::process::ExitCode;

use ipe_sandbox::run_jail::{self, ParseError, RunJailDefect, SandboxProfile};
use scratch::ScratchDir;

/// Exit non-zero, printing a typed error to stderr.
///
/// Using `eprintln!` + `ExitCode::FAILURE` rather than `process::exit` so
/// destructors run — the wrapper holds no resources that matter at exit, but
/// the pattern keeps the type system honest (`!` vs `ExitCode`).
macro_rules! fatal {
    ($($arg:tt)*) => {{
        eprintln!("ipe-wrapper: {}", format_args!($($arg)*));
        return ExitCode::FAILURE;
    }};
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    run(&args)
}

fn run(args: &[OsString]) -> ExitCode {
    let (show_profile, app_args) = split_args(args);

    // Dispatch to the compile-time selected mode.
    #[cfg(embed_mode)]
    {
        run_embed(show_profile, app_args)
    }
    #[cfg(not(embed_mode))]
    {
        run_bundle(show_profile, app_args)
    }
}

/// Split `[wrapper-flags] [-- <app-args>...]` at the first `--`.
///
/// Returns whether `--show-profile` (dump the embedded or on-disk profile text
/// and exit) is among the wrapper flags, and the app arguments. Only the
/// segment before the first `--` is the wrapper's: everything after it,
/// another `--` or `--show-profile` included, belongs to the app.
fn split_args(args: &[OsString]) -> (bool, &[OsString]) {
    let (wrapper_flags, app_args) =
        args.iter()
            .position(|a| a == "--")
            .map_or((args, &[][..]), |i| {
                (
                    args.get(..i).unwrap_or(&[]),
                    args.get(i + 1..).unwrap_or(&[]),
                )
            });
    let show_profile = wrapper_flags.iter().any(|a| a == "--show-profile");
    (show_profile, app_args)
}

// ── Bundle mode ─────────────────────────────────────────────────────────────

/// Bundle-mode entry: locate `ipe-app` and `ipe.profile` by fixed relative
/// paths next to the wrapper binary, verify, and exec.
#[cfg(not(embed_mode))]
fn run_bundle(show_profile: bool, app_args: &[OsString]) -> ExitCode {
    let wrapper_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => fatal!("cannot resolve wrapper binary path: {e}"),
    };
    let Some(parent) = wrapper_path.parent() else {
        fatal!("wrapper binary path has no parent directory");
    };
    let bundle_dir = parent.to_path_buf();

    let app_path = bundle_dir.join("ipe-app");
    let profile_path = bundle_dir.join("ipe.profile");

    // Read and parse the profile strictly before touching the binary (fail
    // early with a clear message on a missing profile).
    let profile_text = match std::fs::read_to_string(&profile_path) {
        Ok(t) => t,
        Err(e) => fatal!(
            "ipe.profile not found at {} — bundle is incomplete or tampered: {e}",
            profile_path.display()
        ),
    };
    let profile = match run_jail::parse_profile(&profile_text) {
        Ok(p) => p,
        Err(ParseError::Malformed { detail }) => fatal!(
            "ipe.profile is malformed ({detail}) — refusing to run with an unparseable profile"
        ),
    };

    if show_profile {
        print!("{profile_text}");
        return ExitCode::SUCCESS;
    }

    // Scan the binary for its embedded floor and verify the profile against it.
    let app_bytes = match std::fs::read(&app_path) {
        Ok(b) => b,
        Err(e) => fatal!(
            "ipe-app not found at {} — bundle is incomplete: {e}",
            app_path.display()
        ),
    };
    exec_after_verify(&app_bytes, &profile, &app_path, app_args)
}

// ── Embed mode ──────────────────────────────────────────────────────────────

/// Embed-mode entry: app binary and profile are baked in at compile time.
///
/// The app bytes come from `OUT_DIR/embedded-app` (copied there by
/// `build.rs`); the profile from `OUT_DIR/embedded-profile`. Both are
/// statically known at compile time — no runtime path lookup, no toolchain.
#[cfg(embed_mode)]
fn run_embed(show_profile: bool, app_args: &[OsString]) -> ExitCode {
    // The build.rs copies the files into OUT_DIR; the macros bake them in. The
    // paths are compile-time constants produced by concat! + env!. `include_str!`
    // embeds the profile as a `&str`, enforcing the UTF-8 invariant at compile
    // time — an invalid-UTF-8 profile fails the build instead of reaching runtime.
    static APP_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/embedded-app"));
    static PROFILE_TEXT: &str = include_str!(concat!(env!("OUT_DIR"), "/embedded-profile"));

    let profile = match run_jail::parse_profile(PROFILE_TEXT) {
        Ok(p) => p,
        Err(ParseError::Malformed { detail }) => fatal!(
            "embedded ipe.profile is malformed ({detail}) — the wrapper was built incorrectly"
        ),
    };

    if show_profile {
        print!("{PROFILE_TEXT}");
        return ExitCode::SUCCESS;
    }

    // Write the embedded binary to a SEALED anonymous file (Linux memfd, sealed
    // against any write/resize; macOS holds the verified bytes for an exclusive
    // in-scratch write).  The capfloor is scanned by reading the SEALED bytes —
    // not the compile-time `APP_BYTES` slice — and the jail materialises the app
    // from that SAME sealed source, so the bytes verified are the bytes exec'd.
    // There is no host path an attacker can pre-seed or swap between verify and
    // exec.
    let sealed = match run_jail::write_sealed_app_memfd(APP_BYTES) {
        Ok(s) => s,
        Err(e) => fatal!("cannot seal embedded binary: {e}"),
    };

    exec_embed_after_verify(&profile, sealed, app_args)
}

// ── Embed-mode verify + exec ─────────────────────────────────────────────────

/// Verify the capability floor against the SEALED bytes and exec the embedded
/// app inside the jail, delivered from the same sealed source — closing the
/// verify/exec identity gap.
///
/// The capfloor is scanned from bytes read through the SEALED descriptor, not
/// from the compile-time `APP_BYTES` slice.  On Linux the jail materialises the
/// app inside the sandbox from the inherited sealed fd via bwrap `--file`; on
/// macOS the verified bytes are written once to an exclusively-created file in
/// the exclusive jail scratch.  Either way, what is verified is what runs.
///
/// Fail-closed on:
/// - read failure on the sealed source
/// - no capfloor marker in the read bytes (missing floor → refuse)
/// - profile does not satisfy the floor (widened profile → refuse)
/// - jail primitive unavailable on this platform
/// - jail establishment failure
#[cfg(embed_mode)]
fn exec_embed_after_verify(
    profile: &SandboxProfile,
    sealed: run_jail::SealedApp,
    app_args: &[OsString],
) -> ExitCode {
    // Read the SEALED bytes for the capfloor scan. These are frozen (Linux
    // seals; macOS in-memory), so a write race cannot diverge them from what
    // the jail will run.
    let sealed_bytes = match sealed.read_sealed_bytes() {
        Ok(b) => b,
        Err(e) => fatal!("cannot read sealed embedded binary: {e}"),
    };

    let Some(floor) = run_jail::scan_capfloor(&sealed_bytes) else {
        fatal!(
            "{}: the binary embeds no capability floor — refusing to run an artifact \
             whose confinement cannot be verified",
            RunJailDefect::ProfileWeakerThanFloor.code().as_str()
        );
    };
    if !profile.satisfies_capfloor(&floor) {
        fatal!("{}", RunJailDefect::ProfileWeakerThanFloor);
    }

    let wants_wall_clock = profile.limits.wall_secs.is_some();
    let tools = match run_jail::probe_run_jail_tools(wants_wall_clock) {
        Ok(t) => t,
        Err(e) => fatal!("{e}"),
    };

    let scoped_tmp = match ScratchDir::new("ipe-wrapper") {
        Ok(d) => d,
        Err(e) => fatal!("cannot create scoped temp dir: {e}"),
    };
    let working_tree = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => fatal!("cannot resolve working directory: {e}"),
    };

    match run_jail::exec_embedded_in_run_jail(
        &tools,
        profile,
        scoped_tmp.path(),
        &working_tree,
        &sealed,
        app_args,
    ) {
        Ok(never) => match never {},
        Err(e) => fatal!("{e}"),
    }
}

// ── Shared verify + exec ─────────────────────────────────────────────────────

/// Scan `app_bytes` for the embedded capability floor, verify `profile`
/// satisfies it, and exec the app at `app_path` inside the jail.
///
/// Bundle mode only: the app is a sibling file on disk. Embed mode uses
/// [`exec_embed_after_verify`], which verifies and delivers from a sealed
/// descriptor instead of a host path.
///
/// Fail-closed on:
/// - no capfloor marker found in `app_bytes` (missing floor → refuse)
/// - profile does not satisfy the floor (widened profile → refuse)
/// - jail primitive unavailable on this platform
/// - jail establishment failure
#[cfg(not(embed_mode))]
fn exec_after_verify(
    app_bytes: &[u8],
    profile: &SandboxProfile,
    app_path: &std::path::Path,
    app_args: &[OsString],
) -> ExitCode {
    // The marker's ABSENCE means the binary was not built with `ipe release`'s
    // embedded floor. Refuse — we cannot verify confinement correctness without
    // the floor.
    let Some(floor) = run_jail::scan_capfloor(app_bytes) else {
        fatal!(
            "{}: the binary embeds no capability floor — refusing to run an artifact \
             whose confinement cannot be verified",
            RunJailDefect::ProfileWeakerThanFloor.code().as_str()
        );
    };

    // The profile must isolate at LEAST as much as the embedded floor.
    // A widened profile (asking for MORE than the floor grants) is refused:
    // the floor is the tamper-proof ceiling on what can be granted.
    if !profile.satisfies_capfloor(&floor) {
        fatal!("{}", RunJailDefect::ProfileWeakerThanFloor);
    }

    // Probe and exec inside the jail. On success (Unix) the process is
    // replaced by the jailed app and this function never returns. On any
    // failure the jail is not established and we refuse.
    let wants_wall_clock = profile.limits.wall_secs.is_some();
    let tools = match run_jail::probe_run_jail_tools(wants_wall_clock) {
        Ok(t) => t,
        Err(e) => fatal!("{e}"),
    };

    let scoped_tmp = match ScratchDir::new("ipe-wrapper") {
        Ok(d) => d,
        Err(e) => fatal!("cannot create scoped temp dir: {e}"),
    };

    let working_tree = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => fatal!("cannot resolve working directory: {e}"),
    };

    match run_jail::exec_in_run_jail(
        &tools,
        profile,
        scoped_tmp.path(),
        &working_tree,
        app_path,
        app_args,
    ) {
        Ok(never) => match never {},
        Err(e) => fatal!("{e}"),
    }
}

// ── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use ipe_sandbox::run_jail::{
        DatabaseAxis, FilesystemScope, SandboxProfile, profile_from_capabilities,
    };
    use std::collections::BTreeSet;

    fn net_profile() -> SandboxProfile {
        profile_from_capabilities(
            &BTreeSet::from([ipe_kernels::Capability::Network]),
            &BTreeSet::new(),
            DatabaseAxis::NotApplicable,
            &[],
        )
        .expect("valid profile")
    }

    fn isolated_profile() -> SandboxProfile {
        SandboxProfile::maximally_isolated()
    }

    /// A profile that exactly matches the floor satisfies it.
    #[test]
    fn profile_satisfies_matching_floor() {
        let profile = net_profile();
        let floor = net_profile();
        assert!(profile.satisfies_capfloor(&floor));
    }

    /// A maximally-isolated profile satisfies any floor (it grants nothing, so
    /// it cannot exceed whatever the floor grants).
    #[test]
    fn isolated_profile_satisfies_any_floor() {
        let profile = isolated_profile();
        let floor = net_profile();
        assert!(profile.satisfies_capfloor(&floor));
    }

    /// A profile widened beyond the floor is refused.
    #[test]
    fn widened_profile_refused_by_floor() {
        let profile = net_profile();
        // Floor grants nothing — the profile's `network=true` exceeds it.
        let floor = isolated_profile();
        assert!(!profile.satisfies_capfloor(&floor));
    }

    /// A profile with an env var the floor does not grant is refused.
    #[test]
    fn env_not_in_floor_refused() {
        let mut profile = isolated_profile();
        profile.env_allowlist = vec!["SECRET".to_owned()];
        let floor = isolated_profile(); // floor grants no env vars
        assert!(!profile.satisfies_capfloor(&floor));
    }

    /// `scan_capfloor` returns `None` for a binary with no floor marker.
    #[test]
    fn no_floor_marker_returns_none() {
        let bytes = b"this binary has no ipe capability floor at all";
        assert!(ipe_sandbox::run_jail::scan_capfloor(bytes).is_none());
    }

    /// A capfloor line round-trips through `to_capfloor_line` + `scan_capfloor`.
    #[test]
    fn capfloor_roundtrip() {
        let profile = net_profile();
        let line = profile.to_capfloor_line();
        let mut payload = line.as_bytes().to_vec();
        payload.push(b'\n');

        let recovered =
            ipe_sandbox::run_jail::scan_capfloor(&payload).expect("marker found in payload");
        assert_eq!(recovered.network, profile.network);
        assert_eq!(recovered.subprocess, profile.subprocess);
        assert!(matches!(recovered.filesystem, FilesystemScope::Isolated));
    }

    /// `--show-profile` is a wrapper flag only before the first `--`.
    #[test]
    fn show_profile_flag_recognized_only_before_the_separator() {
        let args: Vec<std::ffi::OsString> = vec!["--show-profile".into()];
        assert_eq!(super::split_args(&args), (true, &[][..]));
        let args: Vec<std::ffi::OsString> = vec!["--".into(), "--show-profile".into()];
        let (show, app_args) = super::split_args(&args);
        assert!(!show, "an app's `--show-profile` is not the wrapper's");
        assert_eq!(Some(app_args), args.get(1..));
    }

    /// App args after the first `--` are passed through whole, a second `--`
    /// included.
    #[test]
    fn app_args_split_after_first_dash_dash() {
        let args: Vec<std::ffi::OsString> = vec![
            "--show-profile".into(),
            "--".into(),
            "--port".into(),
            "--".into(),
            "8080".into(),
        ];
        let (show, app_args) = super::split_args(&args);
        assert!(show);
        let expected: Vec<std::ffi::OsString> = vec!["--port".into(), "--".into(), "8080".into()];
        assert_eq!(app_args, expected.as_slice());
        assert_eq!(super::split_args(&[]), (false, &[][..]));
    }
}
