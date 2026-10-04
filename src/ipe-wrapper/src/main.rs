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

use ipe_fs_open::{ByteCap, OpenRefusal, RegularFile};
use ipe_sandbox::run_jail::{self, ParseError, SandboxProfile};
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
    let WrapperArgs {
        show_profile,
        app_args,
    } = match split_args(args) {
        Ok(parsed) => parsed,
        Err(UnknownFlag(flag)) => fatal!(
            "unknown wrapper flag {flag:?} — the wrapper takes only `--show-profile`; \
             pass the app's own arguments after `--`"
        ),
    };

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

/// The wrapper's command line: its own flags, then the app's arguments.
#[derive(Debug, PartialEq, Eq)]
struct WrapperArgs<'a> {
    /// Dump the embedded or on-disk profile text and exit.
    show_profile: bool,
    /// Everything after the first `--`, passed to the app whole.
    app_args: &'a [OsString],
}

/// A token before the first `--` that is not a wrapper flag.
#[derive(Debug, PartialEq, Eq)]
struct UnknownFlag(OsString);

/// Split `[wrapper-flags] [-- <app-args>...]` at the first `--`.
///
/// Only the segment before the first `--` is the wrapper's: everything after
/// it, another `--` or `--show-profile` included, belongs to the app.
///
/// # Errors
///
/// [`UnknownFlag`] for any token before the first `--` other than
/// `--show-profile`: an app argument given without the separator is refused,
/// never dropped, so the app never runs with arguments silently missing.
fn split_args(args: &[OsString]) -> Result<WrapperArgs<'_>, UnknownFlag> {
    let (wrapper_flags, app_args) = args.iter().position(|a| a == "--").map_or_else(
        || (args, &[][..]),
        |at| {
            args.split_at_checked(at)
                .map_or((args, &[][..]), |(flags, rest)| {
                    (flags, rest.get(1..).unwrap_or(&[]))
                })
        },
    );
    let mut show_profile = false;
    for flag in wrapper_flags {
        if flag == "--show-profile" {
            show_profile = true;
        } else {
            return Err(UnknownFlag(flag.clone()));
        }
    }
    Ok(WrapperArgs {
        show_profile,
        app_args,
    })
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
    let profile_text = match read_capped(&profile_path, run_jail::PROFILE_READ_CAP)
        .and_then(|bytes| String::from_utf8(bytes).map_err(|_| OpenRefusal::NotUtf8))
    {
        Ok(text) => text,
        Err(refusal) => fatal!(
            "cannot read ipe.profile at {}: {refusal} — refusing to run an incomplete or \
             tampered bundle",
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
    let app_bytes = match read_capped(&app_path, run_jail::APP_READ_CAP) {
        Ok(bytes) => bytes,
        Err(refusal) => fatal!(
            "cannot read ipe-app at {}: {refusal} — refusing to run an incomplete or \
             tampered bundle",
            app_path.display()
        ),
    };
    deliver_bundle_app(&app_bytes, &profile, &app_path, app_args)
}

/// Run the bundle's app from the bytes just read, sealed: the bytes the
/// floor is verified against are the bytes the jail runs, so a swap of
/// `ipe-app` between the read and the exec runs nothing new.
#[cfg(all(
    not(embed_mode),
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos"
    )
))]
fn deliver_bundle_app(
    app_bytes: &[u8],
    profile: &SandboxProfile,
    _app_path: &std::path::Path,
    app_args: &[OsString],
) -> ExitCode {
    let sealed = match run_jail::write_sealed_app_memfd(app_bytes) {
        Ok(s) => s,
        Err(e) => fatal!("cannot seal ipe-app: {e}"),
    };
    exec_sealed_after_verify(profile, &sealed, app_args)
}

/// Run the bundle's app by path on a platform with no sealed delivery.
#[cfg(all(
    not(embed_mode),
    not(any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos"
    ))
))]
fn deliver_bundle_app(
    app_bytes: &[u8],
    profile: &SandboxProfile,
    app_path: &std::path::Path,
    app_args: &[OsString],
) -> ExitCode {
    exec_after_verify(app_bytes, profile, app_path, app_args)
}

/// Read the whole regular file at `path`, refused past `max` bytes.
///
/// The open never blocks and is proven regular on the opened handle
/// ([`RegularFile::open_user_named`]), so a FIFO, device or directory swapped
/// in at the path is refused rather than hung on or read; at most one byte
/// past `max` is ever read.
///
/// # Errors
///
/// The [`OpenRefusal`] the open or read met; [`OpenRefusal::TooLarge`] past
/// `max`; an [`OpenRefusal::Io`] for a zero `max`, which admits no file.
fn read_capped(path: &std::path::Path, max: u64) -> Result<Vec<u8>, OpenRefusal> {
    let Some(cap) = ByteCap::new(max) else {
        return Err(OpenRefusal::Io(std::io::ErrorKind::InvalidInput));
    };
    RegularFile::open_user_named(path)?.read_bytes(cap)
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

    exec_sealed_after_verify(&profile, &sealed, app_args)
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
/// - a development build's floor (not `ipe release build` → refuse)
/// - profile does not satisfy the floor (widened profile → refuse)
/// - jail primitive unavailable on this platform
/// - jail establishment failure
#[cfg(any(
    embed_mode,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos"
))]
fn exec_sealed_after_verify(
    profile: &SandboxProfile,
    sealed: &run_jail::SealedApp,
    app_args: &[OsString],
) -> ExitCode {
    // Read the SEALED bytes for the capfloor scan. These are frozen (Linux
    // seals; macOS in-memory), so a write race cannot diverge them from what
    // the jail will run.
    let sealed_bytes = match sealed.read_sealed_bytes() {
        Ok(b) => b,
        Err(e) => fatal!("cannot read sealed embedded binary: {e}"),
    };

    if let Err(refusal) = run_jail::verify_release_floor(profile, &sealed_bytes) {
        fatal!("{refusal}");
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
        sealed,
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
/// Bundle mode on a platform with no sealed delivery only: the app is a
/// sibling file on disk. Elsewhere `exec_sealed_after_verify` verifies and
/// delivers from a sealed descriptor instead of a host path.
///
/// Fail-closed on:
/// - no capfloor marker found in `app_bytes` (missing floor → refuse)
/// - a development build's floor (not `ipe release build` → refuse)
/// - profile does not satisfy the floor (widened profile → refuse)
/// - jail primitive unavailable on this platform
/// - jail establishment failure
#[cfg(all(
    not(embed_mode),
    not(any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos"
    ))
))]
fn exec_after_verify(
    app_bytes: &[u8],
    profile: &SandboxProfile,
    app_path: &std::path::Path,
    app_args: &[OsString],
) -> ExitCode {
    // A missing floor, a development build's floor, or a profile granting more
    // than the floor (the ceiling on what can be granted) all refuse.
    if let Err(refusal) = run_jail::verify_release_floor(profile, app_bytes) {
        fatal!("{refusal}");
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
    use ipe_fs_open::OpenRefusal;
    use ipe_sandbox::run_jail::{
        DatabaseAxis, FilesystemScope, FloorIntent, FloorRefusal, SandboxProfile,
        profile_from_capabilities, verify_release_floor,
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
        let line = profile.to_capfloor_line(FloorIntent::Release);
        let mut payload = line.as_bytes().to_vec();
        payload.push(b'\n');

        let recovered =
            ipe_sandbox::run_jail::scan_capfloor(&payload).expect("marker found in payload");
        assert_eq!(recovered.intent, FloorIntent::Release);
        assert_eq!(recovered.axes.network, profile.network);
        assert_eq!(recovered.axes.subprocess, profile.subprocess);
        assert!(matches!(
            recovered.axes.filesystem,
            FilesystemScope::Isolated
        ));
    }

    /// The release wrapper refuses an app a development build embedded the floor of.
    #[test]
    fn capfloor_of_a_development_build_is_refused() {
        let profile = net_profile();
        let dev = profile
            .to_capfloor_line(FloorIntent::Development)
            .into_bytes();
        assert_eq!(
            verify_release_floor(&profile, &dev),
            Err(FloorRefusal::NotRelease)
        );
        let release = profile.to_capfloor_line(FloorIntent::Release).into_bytes();
        assert_eq!(verify_release_floor(&profile, &release), Ok(()));
    }

    /// The release wrapper refuses an app that embeds no floor marker.
    #[test]
    fn verify_release_floor_refuses_a_floorless_binary() {
        let profile = net_profile();
        let floorless: &[u8] = b"\x7fELF\x02\x01\x01\0fn main() {}\0";
        assert_eq!(
            verify_release_floor(&profile, floorless),
            Err(FloorRefusal::Unreadable)
        );
        assert_eq!(
            verify_release_floor(&profile, b""),
            Err(FloorRefusal::Unreadable)
        );
    }

    /// A read holds at most the cap: a file at the cap is read whole, one
    /// byte over refuses, and a directory is not a regular file.
    #[test]
    fn read_capped_reads_at_the_cap_and_refuses_one_over() {
        let dir = super::ScratchDir::new("ipe-wrapper-cap").expect("scratch dir");
        let path = dir.path().join("ipe-app");
        std::fs::write(&path, b"0123456789").expect("write app");
        assert_eq!(
            super::read_capped(&path, 10).expect("read"),
            b"0123456789".to_vec()
        );
        assert!(matches!(
            super::read_capped(&path, 9),
            Err(OpenRefusal::TooLarge(_))
        ));
        assert!(matches!(
            super::read_capped(dir.path(), 10),
            Err(OpenRefusal::NotRegular(_))
        ));
        assert_eq!(
            super::read_capped(&dir.path().join("absent"), 10),
            Err(OpenRefusal::Absent)
        );
    }

    /// A FIFO planted where a bundle file belongs is refused at once, never
    /// blocked on waiting for a writer.
    #[cfg(unix)]
    #[test]
    fn read_capped_refuses_a_fifo_without_blocking() {
        let dir = super::ScratchDir::new("ipe-wrapper-fifo").expect("scratch dir");
        let fifo = dir.path().join("ipe.profile");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("run mkfifo");
        assert!(made.success(), "mkfifo failed");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .spawn(move || {
                let _ = tx.send(super::read_capped(&fifo, 1024));
            })
            .expect("spawn the reader");
        let outcome = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("read_capped must not block on a FIFO");
        assert!(
            matches!(outcome, Err(OpenRefusal::NotRegular(_))),
            "a FIFO is not a regular file: {outcome:?}"
        );
    }

    /// `--show-profile` is a wrapper flag only before the first `--`.
    #[test]
    fn show_profile_flag_recognized_only_before_the_separator() {
        let args: Vec<std::ffi::OsString> = vec!["--show-profile".into()];
        assert_eq!(
            super::split_args(&args),
            Ok(super::WrapperArgs {
                show_profile: true,
                app_args: &[]
            })
        );
        let args: Vec<std::ffi::OsString> = vec!["--".into(), "--show-profile".into()];
        let parsed = super::split_args(&args).expect("parses");
        assert!(
            !parsed.show_profile,
            "an app's `--show-profile` is not the wrapper's"
        );
        assert_eq!(Some(parsed.app_args), args.get(1..));
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
        let parsed = super::split_args(&args).expect("parses");
        assert!(parsed.show_profile);
        let expected: Vec<std::ffi::OsString> = vec!["--port".into(), "--".into(), "8080".into()];
        assert_eq!(parsed.app_args, expected.as_slice());
        assert_eq!(
            super::split_args(&[]),
            Ok(super::WrapperArgs {
                show_profile: false,
                app_args: &[]
            })
        );
    }

    /// A token before the first `--` that is not a wrapper flag is refused,
    /// never dropped from the app's arguments.
    #[test]
    fn app_args_split_refuses_an_unknown_token_before_the_separator() {
        for args in [
            vec![std::ffi::OsString::from("--port"), "8080".into()],
            vec!["--show-profile".into(), "serve".into(), "--".into()],
            vec!["--show-profilex".into()],
        ] {
            assert!(
                matches!(super::split_args(&args), Err(super::UnknownFlag(_))),
                "{args:?} must be refused"
            );
        }
    }
}
