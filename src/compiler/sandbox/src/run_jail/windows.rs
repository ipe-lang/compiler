//! The Windows run jail: the Job Object + `AppContainer` + launcher-scrub arms
//! and the `mod windows_jail` Win32 plumbing they drive. The environment-scrub
//! helpers are pure and unit-tested on any host, so they are gated `any(windows,
//! test)` rather than on Windows alone; the OS arms and `mod windows_jail` are
//! Windows-only. Every other target gets the refuse stubs in [`super`].

use std::ffi::{OsStr, OsString};
use std::path::Path;
#[cfg(target_os = "windows")]
use std::path::PathBuf;

use super::SandboxProfile;
#[cfg(target_os = "windows")]
use super::{FilesystemScope, RunJailDefect, RunJailTools};

/// Windows: the run jail's primitives are Win32 kernel objects (a Job Object, an
/// AppContainer lowbox token), built directly through the Windows API rather than
/// by exec'ing an external tool. There is no `bwrap`/`prlimit`/`sandbox-exec`
/// binary to locate, so this returns an inert "primitives are the kernel API"
/// token whose paths are never used for a tool invocation; the real
/// constructibility check — and the fail-closed refusal when a primitive cannot
/// be created — happens inside [`exec_in_run_jail`] at launch, where the objects
/// are actually built.
///
/// `_wants_wall_clock` is unused: the Windows jail carries no external wall-clock
/// helper (a wall clock, if ever added, would be a Job Object time limit, not a
/// separate tool).
///
/// # Errors
///
/// Never on Windows — this probe cannot fail because it locates no external tool;
/// the primitive construction that CAN fail is in [`exec_in_run_jail`], which
/// refuses (never runs unconfined) on any failure.
#[cfg(target_os = "windows")]
#[allow(
    clippy::missing_const_for_fn,
    clippy::unnecessary_wraps,
    clippy::doc_markdown,
    clippy::too_long_first_doc_paragraph
)]
pub fn probe_run_jail_tools(_wants_wall_clock: bool) -> Result<RunJailTools, RunJailDefect> {
    // An inert token: the fields are the same placeholder path, never invoked as a
    // Unix tool. The Windows arm builds its kernel objects directly and does not
    // read these.
    let placeholder = PathBuf::from("windows-run-jail-native");
    Ok(RunJailTools {
        bwrap: placeholder.clone(),
        prlimit: placeholder.clone(),
        timeout: Some(placeholder),
    })
}

/// Run the emitted `app` binary inside the Windows run jail described by
/// `profile` — a Job Object (subprocess axis) around an AppContainer-tokened
/// child (filesystem + network axes) whose environment the launcher scrubs (env
/// axis), assembled per the Windows run-jail design.
///
/// Unlike the Unix arms there is no `exec`-replace on Windows: the launcher stays
/// alive as the Job Object owner (so `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` holds
/// for the app's whole lifetime) and propagates the child's exit code. The launch
/// is create-suspended → assign-to-job → resume, so the app never runs an
/// instruction outside the job.
///
/// Per-axis confinement (see [`platform_confined_axes`]):
/// - **subprocess** — the Job Object caps the active-process count (1 when the
///   axis is withheld, so no child can spawn) and denies breakaway, so no process
///   escapes the container.
/// - **env** — the child's environment block is built from
///   [`windows_scrubbed_env`] and passed explicitly to `CreateProcess`; the
///   launcher's environment is never inherited.
/// - **filesystem + network** — the child runs under an AppContainer lowbox token
///   (deny-by-default): the network capability SID (`internetClient`) is granted
///   only when the profile grants network, and the scratch (plus the working tree
///   when the filesystem axis is granted) is ACLed to the container SID. On a
///   non-ACL volume or where AppContainer cannot be established the arm FAILS
///   CLOSED (refuses) rather than run with an unenforced boundary.
///
/// Fail-closed at every step: a Job Object, token, capability SID, ACL, or
/// `CreateProcess` that cannot be built REFUSES — the capability-bearing app is
/// never run unconfined. Every Win32 handle (job, process, thread, token) is
/// RAII-closed by an owned wrapper, and every allocated SID / attribute list is
/// freed on every path, so a failure cannot leak a handle or leave the app
/// running outside the jail.
///
/// The jail's actual deny behaviour is proven by the `windows-run-jail` CI job on
/// a real `windows-2022` runner (a hosted runner, no Docker daemon needed);
/// this crate builds the arm and unit-tests the pure pieces (the env scrub, the
/// UTF-16 block) on any host.
///
/// # Errors
///
/// Any [`RunJailDefect`]. On success the launcher waits for the jailed child and
/// this returns via [`RunJailDefect::Spawn`] carrying the propagated exit — it is
/// the one arm that returns on SUCCESS (Windows has no `exec`-replace), so the
/// caller reads the exit code from the returned defect's detail. (The signature
/// keeps `Infallible` for arm-parity with the Unix arms; the launcher process
/// exits with the child's code before returning in the success path.)
#[cfg(target_os = "windows")]
#[allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
pub fn exec_in_run_jail(
    _tools: &RunJailTools,
    profile: &SandboxProfile,
    scoped_tmp: &Path,
    working_tree: &Path,
    app: &Path,
    app_args: &[OsString],
) -> Result<std::convert::Infallible, RunJailDefect> {
    windows_jail::launch(profile, scoped_tmp, working_tree, app, app_args)
}

/// Test-only seam: run `app` under the SAME Windows run jail
/// [`exec_in_run_jail`] uses, but RETURN the child's exit code instead of
/// exiting the process. The `windows-run-jail` CI E2E drives the enforce-vs-
/// control duality through this so it can assert on the jailed vs unjailed exit
/// codes without the launcher replacing the test process. It is exactly the
/// production `run_confined` sequence (one jail source, no fork).
///
/// # Errors
///
/// Any [`RunJailDefect`] — a jail that could not be established refuses here just
/// as the production launcher does.
#[cfg(target_os = "windows")]
#[doc(hidden)]
pub fn run_windows_jailed_for_test(
    profile: &SandboxProfile,
    scoped_tmp: &Path,
    working_tree: &Path,
    app: &Path,
    app_args: &[OsString],
) -> Result<u32, RunJailDefect> {
    windows_jail::run_confined(profile, scoped_tmp, working_tree, app, app_args)
}

/// Run `payload` under the SAME Windows jail sequence [`exec_in_run_jail`] uses —
/// a Job Object (subprocess) around an AppContainer-tokened, env-scrubbed child
/// (filesystem + network + env) — and RETURN the child's exit code, so the
/// returning Tier-2 build jail ([`crate::build_jail::build_in_jail`]) can decode
/// it into a [`crate::build_jail::JailOutcome`] rather than replacing the process.
///
/// `payload[0]` is the program and the rest its arguments (the same
/// `&[OsString]` shape the Linux/macOS build-jail arms take). The confinement is
/// the production [`windows_jail::run_confined`] sequence — one jail source, no
/// fork — so a build observed under Tier-2 is confined exactly as the shipped
/// artifact is at run time. Every kernel object (job / token / SID / attribute
/// list) is RAII-released on every path, so the audit's per-axis tightening loop
/// leaks nothing across calls.
///
/// # Errors
///
/// Any [`RunJailDefect`] — a jail that cannot be established (a missing primitive,
/// a non-ACL scratch volume, a `CreateProcessW` failure) refuses here exactly as
/// the production launcher does; the untrusted build is never run unconfined.
#[cfg(target_os = "windows")]
pub fn build_windows_jailed(
    profile: &SandboxProfile,
    scoped_tmp: &Path,
    working_tree: &Path,
    payload: &[OsString],
) -> Result<u32, RunJailDefect> {
    let Some((app, args)) = payload.split_first() else {
        return Err(RunJailDefect::Spawn {
            detail: "empty build-jail payload".to_owned(),
        });
    };
    windows_jail::run_confined(profile, scoped_tmp, working_tree, Path::new(app), args)
}

/// One name every jailed Windows child receives ahead of the profile's allowlist.
///
/// The base set is the launcher's whole fixed env contract: [`windows_scrubbed_env`]
/// emits exactly these names (each when it has a value) plus the profile's
/// allowlisted names, and nothing else. The Windows e2e asserts that the jailed
/// child observes this set.
///
/// - `SystemRoot` — Win32 calls and the loader fail without it.
/// - `PATH` — system tool resolution.
/// - `TMP` / `TEMP` — pointed at the always-writable scratch (different runtimes
///   read different ones).
/// - `LANG` — re-exported when the host sets it, matching the Unix arms.
/// - `LOCALAPPDATA`, `APPDATA`, `USERPROFILE`, `HOMEDRIVE`, `HOMEPATH` — the
///   profile variables `CreateProcessW` reads from the supplied block when it
///   launches an `AppContainer` child. A block without them fails process
///   creation with `ERROR_ENVVAR_NOT_FOUND` (203) before the child runs; with the
///   host's values the child starts. Only the host's values are proven to start
///   it, so each is the host value, re-exported only when the host sets it. The
///   values name host profile folders but grant nothing: the `AppContainer` token
///   reaches only what is granted to the container SID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowsBaseEnv {
    /// `SystemRoot`: the host value, else `C:\Windows`.
    SystemRoot,
    /// `PATH`: the host value when set.
    Path,
    /// `TMP`: the scratch directory.
    Tmp,
    /// `TEMP`: the scratch directory.
    Temp,
    /// `LANG`: the host value when set.
    Lang,
    /// `LOCALAPPDATA`: the host value when set.
    LocalAppData,
    /// `APPDATA`: the host value when set.
    AppData,
    /// `USERPROFILE`: the host value when set.
    UserProfile,
    /// `HOMEDRIVE`: the host value when set.
    HomeDrive,
    /// `HOMEPATH`: the host value when set.
    HomePath,
}

/// Where a [`WindowsBaseEnv`] name takes its value from.
enum BaseEnvValue {
    /// The scratch directory the child may always write.
    Scratch,
    /// The host's value; absent when the host leaves it unset.
    Host,
    /// The host's value, else this fixed default.
    HostOr(&'static str),
}

impl WindowsBaseEnv {
    /// Every base name, in declaration order.
    pub const ALL: [Self; 10] = [
        Self::SystemRoot,
        Self::Path,
        Self::Tmp,
        Self::Temp,
        Self::Lang,
        Self::LocalAppData,
        Self::AppData,
        Self::UserProfile,
        Self::HomeDrive,
        Self::HomePath,
    ];

    /// The variable name as it appears in the child's environment block.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SystemRoot => "SystemRoot",
            Self::Path => "PATH",
            Self::Tmp => "TMP",
            Self::Temp => "TEMP",
            Self::Lang => "LANG",
            Self::LocalAppData => "LOCALAPPDATA",
            Self::AppData => "APPDATA",
            Self::UserProfile => "USERPROFILE",
            Self::HomeDrive => "HOMEDRIVE",
            Self::HomePath => "HOMEPATH",
        }
    }

    const fn value(self) -> BaseEnvValue {
        match self {
            Self::SystemRoot => BaseEnvValue::HostOr("C:\\Windows"),
            Self::Tmp | Self::Temp => BaseEnvValue::Scratch,
            Self::Path
            | Self::Lang
            | Self::LocalAppData
            | Self::AppData
            | Self::UserProfile
            | Self::HomeDrive
            | Self::HomePath => BaseEnvValue::Host,
        }
    }
}

/// The scrubbed `(name, value)` environment pairs the Windows launcher passes to `CreateProcess`.
///
/// This is the `env` axis enforced launcher-side (`lpEnvironment`), mirroring
/// [`crate::build_jail::macos_scrubbed_env`] and the Linux jail's `--clearenv` +
/// re-export. A pure function of the profile and a host-env lookup, so the exact
/// set of variables that survive into the child is unit-testable on any host (the
/// UTF-16 block-building that consumes it is the only Windows-specific step). The
/// child never inherits the launcher's environment: it gets the [`WindowsBaseEnv`]
/// set plus the profile's allowlisted names (and only when the host actually sets
/// them — a granted-but-unset name is simply absent, never a placeholder).
///
/// The returned pairs are sorted by name in Windows' case-insensitive
/// uppercase-ordinal order, the order `CreateProcessW` documents for a
/// `CREATE_UNICODE_ENVIRONMENT` block, and hold no two names that collide
/// case-insensitively.
#[must_use]
pub fn windows_scrubbed_env(
    profile: &SandboxProfile,
    scoped_tmp: &Path,
    host_env: &dyn Fn(&str) -> Option<OsString>,
) -> Vec<(OsString, OsString)> {
    let mut env: Vec<(OsString, OsString)> = Vec::new();
    for base in WindowsBaseEnv::ALL {
        let value = match base.value() {
            BaseEnvValue::Scratch => Some(scoped_tmp.as_os_str().to_owned()),
            BaseEnvValue::Host => host_env(base.name()),
            BaseEnvValue::HostOr(default) => {
                Some(host_env(base.name()).unwrap_or_else(|| OsString::from(default)))
            }
        };
        if let Some(value) = value {
            env.push((OsString::from(base.name()), value));
        }
    }
    // Only the profile's declared env names re-enter, and only when the host
    // actually sets them. An empty name can never form a valid `NAME=VALUE` entry
    // (Windows rejects a block containing one), so a granted-but-empty name is
    // dropped fail-closed rather than emitted as a malformed entry.
    for name in &profile.env_allowlist {
        if name.is_empty() {
            continue;
        }
        if let Some(value) = host_env(name) {
            env.push((OsString::from(name), value));
        }
    }
    // Windows sorts an environment block by name, case-insensitively, in
    // UPPERCASE-ordinal collation. The distinction from a lowercase sort is
    // load-bearing: lowercasing puts `_` (0x5F) BEFORE the letters (`a`..=`z` =
    // 0x61..=0x7A), whereas Windows uppercases and so puts `_` AFTER the letters
    // (`A`..=`Z` = 0x41..=0x5A). Sort by name only (an env name cannot contain
    // `=`).
    env.sort_by_key(|(name, _)| env_name_collation_key(name));
    // The environment is case-insensitive on Windows, so a block holding two names
    // that collide under the collation key is malformed. The profile parser accepts
    // an `env` name that collides with a base name (e.g. a granted `SystemRoot`
    // or `Path`), so drop any later collision, keeping the first: the base wins
    // over an allowlist re-grant, so a granted name can never displace a scrubbed base
    // to a different value. A stable sort keeps the base entry ahead of an allowlist
    // duplicate (the base was pushed first), so first-kept is fail-closed.
    env.dedup_by_key(|(name, _)| env_name_collation_key(name));
    env
}

/// The case-insensitive collation key a `CREATE_UNICODE_ENVIRONMENT` block is sorted on.
///
/// Windows compares environment names by UPPERCASE ordinal, so the block is sorted
/// on the ASCII-uppercased name. Sorting on the lowercased name instead reorders any
/// name containing a character that case-folds across the letter range (`_` most
/// notably).
///
/// Pure and host-independent (the produced pairs are unit-tested on any host); env
/// names are ASCII, so ASCII-uppercasing reproduces Windows' uppercase-ordinal order
/// over the range names actually use.
fn env_name_collation_key(name: &OsStr) -> String {
    name.to_string_lossy().to_ascii_uppercase()
}

/// An `OsStr` as UTF-16LE code units for the environment block. On Windows this is
/// the exact `encode_wide` of the underlying wide string (a path may hold a wide
/// unit no UTF-8 round-trip preserves, so the child receives it losslessly); off
/// Windows (the unit-test hosts) the lossy UTF-8 view suffices because the block
/// bytes are only asserted for ASCII names/values that round-trip identically.
#[cfg(windows)]
fn os_to_utf16(s: &OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt as _;
    s.encode_wide().collect()
}

// Compiled only for the unit tests off Windows (the block builder that calls it is
// Windows-production / any-host-test); the Windows arm always uses the exact
// `encode_wide` variant above.
#[cfg(all(not(windows), test))]
fn os_to_utf16(s: &OsStr) -> Vec<u16> {
    s.to_string_lossy().encode_utf16().collect()
}

/// The scrubbed environment as a doubly-NUL-terminated UTF-16LE block for
/// `CreateProcess` `lpEnvironment` under `CREATE_UNICODE_ENVIRONMENT`: each surviving
/// pair as `NAME=VALUE\0`, in the case-insensitive uppercase-ordinal name order
/// Windows requires, closed by a final extra NUL (so a non-empty block ends `\0\0`
/// and an empty block is a lone `\0\0`).
///
/// Pure and host-independent: it consumes the pairs [`windows_scrubbed_env`] already
/// scrubbed and sorted, so the exact bytes handed to `CreateProcessW` are asserted by
/// unit tests on any host — the Windows arm's `env_block_utf16` is a thin wrapper over
/// this. An entry with an empty name can never form a valid `NAME=VALUE` (Windows
/// rejects a block containing one), so the pair source drops empty names before this
/// point; this builder therefore only ever encodes well-formed entries.
// Windows production (the arm's `env_block_utf16` wraps it) plus the any-host unit
// tests that assert its exact bytes; nothing else on a non-Windows host calls it.
#[cfg(any(windows, test))]
#[must_use]
fn env_block_from_pairs(pairs: &[(OsString, OsString)]) -> Vec<u16> {
    let mut block: Vec<u16> = Vec::new();
    for (name, value) in pairs {
        block.extend(os_to_utf16(name));
        block.push(u16::from(b'='));
        block.extend(os_to_utf16(value));
        block.push(0);
    }
    // A non-empty block already ends in the last entry's own NUL; this appends the
    // block terminator (giving `\0\0`). An empty block needs both NULs written here
    // so `CreateProcess` reads a valid empty environment rather than running past a
    // lone terminator.
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    block
}

/// The access mask the container SID is granted on the scratch and a granted
/// working tree: `FILE_GENERIC_READ | FILE_GENERIC_WRITE`.
///
/// It carries neither `DELETE` nor `FILE_DELETE_CHILD`, so the child cannot
/// unlink or rename an entry the grant did not give it; it can still create and
/// write entries, which is why a tree holding version-control metadata is
/// refused ([`windows_working_tree_plan`]).
#[cfg(any(windows, test))]
pub const WORKING_TREE_GRANT_MASK: u32 = 0x0012_019F;

/// The path the Windows jail grants read-write for `tree`, which it grants only
/// when the tree holds no version-control metadata.
///
/// The grant is an inheritable allow ACE over the whole tree, and a carve needs
/// a deny ACE written over each carved path; until the arm writes one, a tree
/// holding metadata is refused.
///
/// # Errors
/// [`crate::JailPathError::VcsMetadataUncarvable`] naming the first carved path
/// when the carve is not empty.
#[cfg(any(windows, test))]
pub fn windows_working_tree_plan(
    tree: &crate::WritableTree,
) -> Result<&crate::CanonicalPath, crate::JailPathError> {
    tree.carve().paths().next().map_or_else(
        || Ok(tree.tree()),
        |first| {
            Err(crate::JailPathError::VcsMetadataUncarvable {
                arm: crate::JailArm::Windows,
                path: first.as_path().to_path_buf(),
            })
        },
    )
}

/// The Windows run-jail launcher: assembles the Job Object + AppContainer token +
/// scrubbed environment and launches the app confined, fail-closed at every step.
///
/// Every raw Win32 call is wrapped in a small checked helper here; every HANDLE
/// is owned by [`OwnedHandle`] (closed on drop, so no failure path leaks a handle
/// or leaves the child running outside the job), every allocated SID / attribute
/// list is freed on every path, and any construction failure returns a
/// [`RunJailDefect`] — the capability-bearing app is NEVER launched unconfined.
// The launcher's doc comments name Win32 APIs and multi-word OS proper nouns
// (Job Object, AppContainer, CreateProcess) throughout; backticking every
// occurrence adds noise without clarity, and the Win32 argument-count is
// intrinsic to the API surface. Scoped allows for exactly those doc/style lints;
// every soundness lint stays enforced.
//
// `unsafe` stays denied module-wide: the Job Object lifecycle (create, assign,
// close) goes through the safe `win32job` crate, and only the functions that
// call a Win32 entry point no vetted safe crate wraps opt in, each with its own
// `#[allow(unsafe_code)]` audit and a SAFETY argument per block.
#[cfg(target_os = "windows")]
#[allow(
    clippy::doc_markdown,
    clippy::too_long_first_doc_paragraph,
    clippy::too_many_arguments
)]
mod windows_jail {
    use super::{FilesystemScope, RunJailDefect, SandboxProfile, windows_scrubbed_env};
    use std::ffi::{OsStr, OsString};
    use std::os::windows::ffi::OsStrExt as _;
    use std::path::Path;

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
        S_OK, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, SET_ACCESS, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID,
        TRUSTEE_IS_USER, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::Isolation::{
        CreateAppContainerProfile, DeleteAppContainerProfile,
        DeriveAppContainerSidFromAppContainerName,
    };
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, FreeSid, GetTokenInformation, NO_INHERITANCE, PSID,
        SECURITY_CAPABILITIES, SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES,
        SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_QUERY, TOKEN_USER, TokenUser,
        WELL_KNOWN_SID_TYPE, WinCapabilityInternetClientSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_TRAVERSE, GetVolumeInformationW,
        GetVolumePathNameW,
    };
    use windows_sys::Win32::System::JobObjects::{
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_JOB_MEMORY,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_TIME,
        JOBOBJECT_BASIC_LIMIT_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectExtendedLimitInformation, SetInformationJobObject,
    };
    use windows_sys::Win32::System::SystemServices::{FILE_PERSISTENT_ACLS, SE_GROUP_ENABLED};
    use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
        DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
        GetExitCodeProcess, InitializeProcThreadAttributeList, OpenProcessToken,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, ResumeThread,
        STARTUPINFOEXW, STARTUPINFOW, UpdateProcThreadAttribute, WaitForSingleObject,
    };

    /// Access rights ACLed onto a granted path for the container SID (read+write).
    const FILE_RW: u32 = super::WORKING_TREE_GRANT_MASK;

    /// Keep the pure [`super::WORKING_TREE_GRANT_MASK`] (whose missing delete
    /// rights a host-independent test pins) equal to the Win32 read+write rights.
    // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); it fails the build if the cross-platform mask drifts from the Win32 constants [ledger #boundary]
    const _: () = assert!(FILE_RW == FILE_GENERIC_READ | FILE_GENERIC_WRITE);

    /// Inheritance of the read+write grants: every file and subdirectory below a
    /// granted root, present and future, carries the grant.
    const GRANT_INHERITANCE: u32 = SUB_CONTAINERS_AND_OBJECTS_INHERIT;

    /// Keep the pure, cross-platform [`crate::run_jail::FILE_PERSISTENT_ACLS_FLAG`] (used by
    /// the host-independent volume-capability decision + its unit tests) in
    /// lockstep with the real Win32 value from `windows-sys`. If they ever diverge
    /// this fails the Windows build.
    // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); it fails the build if the cross-platform flag drifts from the Win32 constant [ledger #boundary]
    const _: () = assert!(crate::run_jail::FILE_PERSISTENT_ACLS_FLAG == FILE_PERSISTENT_ACLS);

    /// An owned Win32 `HANDLE` closed on drop — RAII so no error path leaks a
    /// handle. A null/`INVALID_HANDLE_VALUE` handle is treated as "nothing to
    /// close".
    struct OwnedHandle(HANDLE);

    impl OwnedHandle {
        const fn get(&self) -> HANDLE {
            self.0
        }
    }

    impl Drop for OwnedHandle {
        #[allow(unsafe_code)]
        // IPE-RUST-AUDIT:ACCEPTED — Win32 FFI that no vetted safe crate wraps; SAFETY per block.
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                // SAFETY: `self.0` is a live handle this type owns; closing it once
                // on drop is the RAII contract, and no copy of it is used after.
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    /// An owned AppContainer SID (`FreeSid` on drop). Allocated by
    /// `DeriveAppContainerSidFromAppContainerName`.
    struct OwnedSid(PSID);

    impl Drop for OwnedSid {
        #[allow(unsafe_code)]
        // IPE-RUST-AUDIT:ACCEPTED — Win32 FFI that no vetted safe crate wraps; SAFETY per block.
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` was allocated by a SID-allocating Win32 call this
                // type owns; `FreeSid` releases it exactly once on drop.
                unsafe {
                    FreeSid(self.0);
                }
            }
        }
    }

    /// A NUL-terminated UTF-16 string for a Win32 wide-string argument.
    fn wide(s: &OsStr) -> Vec<u16> {
        let mut v: Vec<u16> = s.encode_wide().collect();
        v.push(0);
        v
    }

    fn spawn(detail: impl Into<String>) -> RunJailDefect {
        RunJailDefect::Spawn {
            detail: detail.into(),
        }
    }

    #[allow(unsafe_code)]
    // IPE-RUST-AUDIT:ACCEPTED — Win32 FFI that no vetted safe crate wraps; SAFETY per block.
    fn last_error_spawn(context: &str) -> RunJailDefect {
        // SAFETY: `GetLastError` reads this thread's last-error slot; no memory
        // is accessed.
        let code = unsafe { GetLastError() };
        spawn(format!("{context} (GetLastError = {code})"))
    }

    /// The launcher entry point: run the app confined, then exit this launcher
    /// with the child's code (Windows has no `exec`-replace, so the launcher stays
    /// alive as the job owner and propagates the exit). Fails closed on any step.
    pub(super) fn launch(
        profile: &SandboxProfile,
        scoped_tmp: &Path,
        working_tree: &Path,
        app: &Path,
        app_args: &[OsString],
    ) -> Result<std::convert::Infallible, RunJailDefect> {
        let code = run_confined(profile, scoped_tmp, working_tree, app, app_args)?;
        // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — jail exec process control: the launcher is the job owner and replaces itself with the confined child's exit code (returns Infallible) [ledger #boundary]
        std::process::exit(i32::from_ne_bytes(code.to_ne_bytes()));
    }

    /// Run the app confined and RETURN its exit code (never exits the launcher) —
    /// the whole Job-Object + AppContainer + scrubbed-env sequence, fail-closed at
    /// every step. [`launch`] wraps this and exits with the code; the CI E2E calls
    /// the [`super::run_windows_jailed_for_test`] seam so it can assert on the
    /// enforce-vs-control exit codes without the launcher replacing the test
    /// process.
    pub(super) fn run_confined(
        profile: &SandboxProfile,
        scoped_tmp: &Path,
        working_tree: &Path,
        app: &Path,
        app_args: &[OsString],
    ) -> Result<u32, RunJailDefect> {
        // 0. A writable working tree holding version-control metadata is refused
        //    before any container exists: the grant cannot keep it read-only.
        if profile.filesystem == FilesystemScope::WorkingTreeReadWrite {
            let tree = crate::CanonicalPath::resolve(working_tree).map_err(RunJailDefect::Path)?;
            let tmp = crate::CanonicalPath::resolve(scoped_tmp).map_err(RunJailDefect::Path)?;
            let home = crate::home::home_dir().map_or_else(
                |_| crate::Home::unknown(),
                |home| crate::covers::vcs_home_of(&home),
            );
            let writable =
                crate::WritableTree::parse(tree, &[&tmp], &home).map_err(RunJailDefect::Path)?;
            super::windows_working_tree_plan(&writable).map_err(RunJailDefect::Path)?;
        }

        // 1. Derive a per-run AppContainer SID from a unique per-run name. The
        //    profile is created (idempotently) so the SID is registerable, then
        //    deleted after the SID is derived — the SID outlives the profile.
        let container_name = per_run_container_name();
        let container = AppContainer::create(&container_name)?;

        // 2. Capability SIDs: internetClient iff the profile grants network. An
        //    absent capability ⇒ outbound connect denied by AppContainer network
        //    isolation (deny-by-default).
        let mut capabilities = CapabilitySids::new();
        if profile.network {
            capabilities.push_well_known(WinCapabilityInternetClientSid)?;
        }

        // 3. ACL the granted resources to the container SID (deny-by-default: only
        //    what is ACLed is reachable). Always the scratch; the working tree only
        //    under the filesystem axis. A failed ACL refuses (never run with an
        //    unenforced write boundary).
        //
        //    Before ACLing, PROVE each path lives on a volume that persists+enforces
        //    DACLs (`FILE_PERSISTENT_ACLS`). On a non-ACL volume (FAT/exFAT) the ACL
        //    is a silent no-op — `SetNamedSecurityInfoW` returns success while
        //    enforcing nothing — so the filesystem boundary the admit path already
        //    trusted would not exist. The probe fails closed, keeping the
        //    always-confined `Filesystem` claim honest.
        probe_volume_persists_acls(scoped_tmp)?;
        acl_path_for_container(scoped_tmp, container.sid())?;
        // The AppContainer token must be able to TRAVERSE every ancestor directory
        // between the volume root and the scratch in order for CreateProcessW to
        // resolve `scoped_tmp` as `lpCurrentDirectory`. ACLing the scratch itself
        // is not enough: Windows path resolution walks each component, and a
        // directory that denies `FILE_TRAVERSE` to the container SID stops the
        // walk, so CreateProcessW cannot start the child there. This grants the
        // minimal traverse right on each ancestor up to (but not including) the
        // volume root, which already allows traversal to everyone by default. The
        // grant is additive (not a replace-DACL), so it never removes existing
        // permissions.
        grant_traverse_to_ancestors(scoped_tmp, container.sid())?;
        if profile.filesystem == FilesystemScope::WorkingTreeReadWrite {
            probe_volume_persists_acls(working_tree)?;
            acl_path_for_container(working_tree, container.sid())?;
        }

        // 4. The Job Object: kill-on-close, no breakaway (never set), active-process
        //    cap = 1 when subprocess withheld else the profile's proc cap.
        let job = create_job(profile)?;

        // 5. The scrubbed environment block (never inherit the launcher's).
        let host_env = crate::host_env::granted;
        let env_block = env_block_utf16(profile, scoped_tmp, &host_env);

        // 6. CreateProcess suspended, with the AppContainer security-capabilities
        //    attribute and the scrubbed environment. The child's current directory
        //    is the always-ACLed scratch — the ONE directory the container token can
        //    always reach. The working tree cannot be the CWD: under a
        //    filesystem-withholding profile it is NOT ACLed to the container SID, so
        //    CreateProcessW could not resolve the current directory for the child.
        //    The CWD is not a capability, so scratch-as-CWD neither grants nor
        //    widens any axis.
        let child = create_suspended_appcontainer_process(
            app,
            app_args,
            scoped_tmp,
            &container,
            &mut capabilities,
            &env_block,
        )?;

        // 7. Assign to the job BEFORE resuming, so no instruction runs un-jobbed.
        assign_to_job(&job, child.process.get())?;

        // 8. Resume the main thread.
        resume(child.thread.get())?;

        // 9. Wait for the jailed child; the job handle stays open (kill-on-close
        //    holds for the child's lifetime). Then tear down the container profile
        //    and return the child's code.
        let code = wait_and_exit_code(child.process.get())?;
        drop(child);
        drop(job);
        drop(capabilities);
        container.delete();
        Ok(code)
    }

    /// A per-run AppContainer name: unique enough that concurrent `ipe dev run`
    /// invocations do not collide on the same container profile.
    fn per_run_container_name() -> OsString {
        let pid = std::process::id();
        // A monotonic-ish suffix from the process id and a coarse time; the SID is
        // per-run and torn down, so uniqueness within the host at this instant is
        // all that is needed.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        OsString::from(format!("ipe.run.jail.{pid}.{nanos}"))
    }

    /// An AppContainer profile + its derived container SID. The profile is deleted
    /// explicitly via [`Self::delete`] after launch; the SID is freed on drop.
    struct AppContainer {
        name: Vec<u16>,
        sid: OwnedSid,
    }

    impl AppContainer {
        #[allow(unsafe_code)]
        // IPE-RUST-AUDIT:ACCEPTED — Win32 FFI that no vetted safe crate wraps; SAFETY per block.
        fn create(name: &OsStr) -> Result<Self, RunJailDefect> {
            let wname = wide(name);
            // CreateAppContainerProfile registers the container so its SID is
            // derivable. ERROR_ALREADY_EXISTS is tolerated (a stale same-name
            // profile), any other failure refuses.
            // The derived SID from CreateAppContainerProfile is discarded here (we
            // re-derive it by name below into the owned SID); it must still be a
            // valid out-pointer.
            let mut created_sid: PSID = std::ptr::null_mut();
            // SAFETY: `wname` is a live NUL-terminated wide string; the display
            // name / description point at the same buffer (only used for
            // registration); no capabilities are attached at profile creation;
            // `created_sid` is a live out-pointer.
            let hr = unsafe {
                CreateAppContainerProfile(
                    wname.as_ptr(),
                    wname.as_ptr(),
                    wname.as_ptr(),
                    std::ptr::null(),
                    0,
                    std::ptr::from_mut(&mut created_sid),
                )
            };
            // The profile-creation SID (when returned) is owned by the caller;
            // free it — the launcher uses the by-name derivation below.
            if !created_sid.is_null() {
                // SAFETY: `created_sid` was allocated by CreateAppContainerProfile.
                unsafe {
                    FreeSid(created_sid);
                }
            }
            if hr != S_OK {
                // HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) is acceptable.
                let already = HRESULT_ALREADY_EXISTS;
                if hr != already {
                    return Err(spawn(format!(
                        "CreateAppContainerProfile failed (HRESULT = {hr:#x}); refusing to run \
                         unconfined"
                    )));
                }
            }
            // Derive the container SID from the registered name.
            let mut sid: PSID = std::ptr::null_mut();
            // SAFETY: `wname` is a live NUL-terminated wide string; `sid` receives a
            // freshly allocated SID on success (freed by OwnedSid on drop).
            let hr = unsafe {
                DeriveAppContainerSidFromAppContainerName(
                    wname.as_ptr(),
                    std::ptr::from_mut(&mut sid),
                )
            };
            if hr != S_OK || sid.is_null() {
                // Best-effort profile cleanup before refusing.
                // SAFETY: `wname` is a live NUL-terminated wide string.
                unsafe {
                    DeleteAppContainerProfile(wname.as_ptr());
                }
                return Err(spawn(format!(
                    "DeriveAppContainerSidFromAppContainerName failed (HRESULT = {hr:#x}); \
                     refusing to run unconfined"
                )));
            }
            Ok(Self {
                name: wname,
                sid: OwnedSid(sid),
            })
        }

        const fn sid(&self) -> PSID {
            self.sid.0
        }

        #[allow(unsafe_code)]
        // IPE-RUST-AUDIT:ACCEPTED — Win32 FFI that no vetted safe crate wraps; SAFETY per block.
        fn delete(&self) {
            // SAFETY: `self.name` is the live NUL-terminated wide name used to
            // create the profile; deleting it releases the registered container.
            unsafe {
                DeleteAppContainerProfile(self.name.as_ptr());
            }
        }
    }

    /// `HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)` — the tolerated
    /// already-registered profile result. Built by the standard HRESULT-from-Win32
    /// bit layout (`0x8007_0000 | (code & 0xFFFF)`) as a bit pattern reinterpreted
    /// into the signed `HRESULT` (`i32`), avoiding a wrapping `as` cast.
    const HRESULT_ALREADY_EXISTS: i32 =
        i32::from_ne_bytes((0x8007_0000u32 | (ERROR_ALREADY_EXISTS & 0xFFFF)).to_ne_bytes());

    /// The AppContainer capability SIDs (network etc.), each a well-known SID this
    /// type allocates and frees on drop, held alongside the `SID_AND_ATTRIBUTES`
    /// array `SECURITY_CAPABILITIES` points at.
    struct CapabilitySids {
        sids: Vec<OwnedWellKnownSid>,
        attrs: Vec<SID_AND_ATTRIBUTES>,
    }

    impl CapabilitySids {
        const fn new() -> Self {
            Self {
                sids: Vec::new(),
                attrs: Vec::new(),
            }
        }

        fn push_well_known(&mut self, kind: WELL_KNOWN_SID_TYPE) -> Result<(), RunJailDefect> {
            let sid = OwnedWellKnownSid::create(kind)?;
            self.sids.push(sid);
            Ok(())
        }

        /// Build the `SID_AND_ATTRIBUTES` array (each enabled) and return a
        /// `SECURITY_CAPABILITIES` referencing the container SID + this array. The
        /// returned struct borrows `self`, so `self` must outlive the CreateProcess
        /// call — the launcher keeps it alive until after the process is created.
        fn security_capabilities(&mut self, container_sid: PSID) -> SECURITY_CAPABILITIES {
            self.attrs.clear();
            for owned in &self.sids {
                self.attrs.push(SID_AND_ATTRIBUTES {
                    Sid: owned.as_psid(),
                    // `SE_GROUP_ENABLED` is declared `i32`; the field is `u32`.
                    #[allow(clippy::cast_sign_loss)]
                    Attributes: SE_GROUP_ENABLED as u32,
                });
            }
            // The capability count is at most a handful of SIDs — never near
            // u32::MAX — so the conversion is total in practice; use a saturating
            // try_from rather than a wrapping cast.
            let cap_count = u32::try_from(self.attrs.len()).unwrap_or(u32::MAX);
            let (cap_ptr, cap_count) = if self.attrs.is_empty() {
                (std::ptr::null_mut(), 0)
            } else {
                (self.attrs.as_mut_ptr(), cap_count)
            };
            SECURITY_CAPABILITIES {
                AppContainerSid: container_sid,
                Capabilities: cap_ptr,
                CapabilityCount: cap_count,
                Reserved: 0,
            }
        }
    }

    /// A well-known capability SID allocated with `CreateWellKnownSid` into an
    /// owned heap buffer; no separate free is needed (the buffer owns the SID's
    /// storage, released when the buffer drops). The `PSID` is derived from the
    /// buffer on demand, so the pointer can never outlive the allocation.
    struct OwnedWellKnownSid {
        buf: Vec<u8>,
    }

    impl OwnedWellKnownSid {
        #[allow(unsafe_code)]
        // IPE-RUST-AUDIT:ACCEPTED — Win32 FFI that no vetted safe crate wraps; SAFETY per block.
        fn create(kind: WELL_KNOWN_SID_TYPE) -> Result<Self, RunJailDefect> {
            use windows_sys::Win32::Security::CreateWellKnownSid;
            let mut buf: Vec<u8> = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
            // The buffer is SECURITY_MAX_SID_SIZE bytes (a small constant), so the
            // length always fits a u32.
            let mut size: u32 = u32::try_from(buf.len()).unwrap_or(u32::MAX);
            // SAFETY: `buf` is a live buffer of SECURITY_MAX_SID_SIZE bytes; the
            // call writes the SID into it and updates `size`.
            let ok = unsafe {
                CreateWellKnownSid(
                    kind,
                    std::ptr::null_mut(),
                    buf.as_mut_ptr().cast(),
                    std::ptr::from_mut(&mut size),
                )
            };
            if ok == 0 {
                return Err(last_error_spawn("CreateWellKnownSid failed"));
            }
            Ok(Self { buf })
        }

        /// The SID pointer into the owned buffer. Valid for as long as `self` (and
        /// so the buffer) lives — the caller keeps the `OwnedWellKnownSid` alive
        /// across the `CreateProcess` call that reads it.
        const fn as_psid(&self) -> PSID {
            self.buf.as_ptr().cast::<std::ffi::c_void>().cast_mut()
        }
    }

    /// The size of a `T` as a Win32 `u32` byte count. Every struct passed to a
    /// Win32 call here is far smaller than `u32::MAX`, so the conversion is total;
    /// `try_from` avoids a wrapping `as` cast and never panics.
    fn size_u32<T>() -> u32 {
        u32::try_from(std::mem::size_of::<T>()).unwrap_or(u32::MAX)
    }

    /// Create the Job Object and set its extended limits: kill-on-close, no
    /// breakaway, active-process cap.
    ///
    /// The job is created, assigned, and closed on drop through the safe
    /// `win32job` crate; its limit setters cover none of the active-process,
    /// job-memory, or per-process CPU-time ceilings, so those are applied with a
    /// raw `SetInformationJobObject` on the job's borrowed handle.
    #[allow(unsafe_code)]
    // IPE-RUST-AUDIT:ACCEPTED — Win32 FFI that no vetted safe crate wraps; SAFETY per block.
    fn create_job(profile: &SandboxProfile) -> Result<win32job::Job, RunJailDefect> {
        let job = win32job::Job::create().map_err(|e| {
            spawn(format!(
                "CreateJobObjectW failed: {}",
                std::io::Error::from(e)
            ))
        })?;

        let active_cap = active_process_cap(profile);
        // The address-space and CPU-second ceilings the profile mandates. On the
        // Unix arms these are `prlimit --as`/`--cpu`; the Job Object enforces the
        // equivalents so a runaway or memory-bomb under an untrusted `ipe dev run` is
        // bounded on every platform, not just Unix (PRINCIPLES.md: bounded by
        // construction — a process that could exhaust host memory or spin forever
        // has broken soundness, and over the network principle 1's exhaustion
        // clause too). `JobMemoryLimit` caps the job's committed bytes;
        // `PerProcessUserTimeLimit` (100-ns units) caps each process's CPU time —
        // exceeding either terminates the whole job.
        let mem_bytes = profile.limits.job_memory_limit_bytes();
        let cpu_100ns = profile.limits.cpu_time_100ns();

        let info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
            BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
                // KILL_ON_JOB_CLOSE: every process dies when the launcher's job handle
                // closes. ACTIVE_PROCESS: the count cap. PROCESS_TIME: the per-process
                // CPU-second ceiling. JOB_MEMORY: the job-wide committed-bytes ceiling.
                // BREAKAWAY_OK is deliberately NOT set — a child cannot escape the job.
                LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                    | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                    | JOB_OBJECT_LIMIT_PROCESS_TIME
                    | JOB_OBJECT_LIMIT_JOB_MEMORY,
                ActiveProcessLimit: active_cap,
                PerProcessUserTimeLimit: cpu_100ns,
                ..JOBOBJECT_BASIC_LIMIT_INFORMATION::default()
            },
            JobMemoryLimit: mem_bytes,
            ..JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default()
        };

        // SAFETY: `info` is a fully-initialized extended-limit struct; the call
        // reads `size_of::<…>()` bytes from it and applies them to the job, whose
        // handle `job` owns and keeps open across the call.
        let ok = unsafe {
            SetInformationJobObject(
                job_handle(&job),
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&info).cast(),
                size_u32::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>(),
            )
        };
        if ok == 0 {
            return Err(last_error_spawn("SetInformationJobObject failed"));
        }
        Ok(job)
    }

    /// The raw Win32 handle of `job`, borrowed for a call `win32job` does not
    /// wrap; `job` keeps ownership and closes it on drop.
    fn job_handle(job: &win32job::Job) -> HANDLE {
        std::ptr::with_exposed_provenance_mut(usize::from_ne_bytes(job.handle().to_ne_bytes()))
    }

    /// ACL a path's DACL to grant read+write to exactly two trustees — the
    /// AppContainer SID (so the sandboxed process can reach its scratch/working
    /// tree) and the launcher's own user SID (so this process and SYSTEM keep the
    /// access post-run cleanup — `remove_dir_all(scoped_tmp)` — needs). These two
    /// replace every explicit entry of `path`'s DACL. Unless that DACL is
    /// protected, `SetNamedSecurityInfoW` also keeps the entries `path` inherits
    /// from its parent; those name host principals, never this per-run container
    /// SID (the ancestor traverse grant does not inherit), so the container
    /// reaches only what these two grants give it. The launcher grant does NOT
    /// widen the sandboxed app's reach: the AppContainer process runs as the
    /// container SID, never as the launcher user. A failure refuses — never run
    /// with an unenforced write boundary.
    ///
    /// Both grants inherit to every file and directory below `path`
    /// ([`GRANT_INHERITANCE`]): a granted root is granted as a whole subtree. A
    /// grant on the root alone leaves every entry the child creates (and every
    /// entry already in a granted working tree) without the container SID, so the
    /// child could create a file but not reopen it, and could not write inside a
    /// directory it made.
    ///
    /// The caller must have already established, via
    /// [`probe_volume_persists_acls`], that `path` lives on a volume with
    /// `FILE_PERSISTENT_ACLS`; on a non-ACL volume (FAT/exFAT) `SetNamedSecurityInfoW`
    /// would return success while enforcing nothing, so the probe fails closed
    /// upstream rather than letting this establish a no-op boundary. That
    /// probe → refuse decision is unit-tested through the pure
    /// [`crate::run_jail::volume_flags_confine_filesystem`].
    #[allow(unsafe_code)]
    // IPE-RUST-AUDIT:ACCEPTED — Win32 FFI that no vetted safe crate wraps; SAFETY per block.
    fn acl_path_for_container(path: &Path, container_sid: PSID) -> Result<(), RunJailDefect> {
        // The launcher's user SID, kept alive in an owned buffer for the whole
        // `SetEntriesInAclW` call (the EXPLICIT_ACCESS entry borrows the SID by
        // pointer).
        let launcher_sid_buf = launcher_user_sid_buffer()?;
        // SAFETY: `launcher_sid_buf` holds a live `TOKEN_USER` whose `User.Sid`
        // points into the same buffer; the read is a plain field access of a
        // populated, correctly aligned structure that outlives every use below.
        let launcher_sid: PSID = unsafe {
            let token_user = launcher_sid_buf.as_ptr().cast::<TOKEN_USER>();
            (*token_user).User.Sid
        };
        if launcher_sid.is_null() {
            return Err(spawn(format!(
                "launcher user SID was null for {}; refusing to run without a cleanup grant",
                path.display()
            )));
        }
        let entries = [
            EXPLICIT_ACCESS_W {
                grfAccessPermissions: FILE_RW,
                grfAccessMode: SET_ACCESS,
                grfInheritance: GRANT_INHERITANCE,
                Trustee: TRUSTEE_W {
                    pMultipleTrustee: std::ptr::null_mut(),
                    MultipleTrusteeOperation: 0,
                    TrusteeForm: TRUSTEE_IS_SID,
                    TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                    ptstrName: container_sid.cast(),
                },
            },
            EXPLICIT_ACCESS_W {
                grfAccessPermissions: FILE_RW,
                grfAccessMode: SET_ACCESS,
                grfInheritance: GRANT_INHERITANCE,
                Trustee: TRUSTEE_W {
                    pMultipleTrustee: std::ptr::null_mut(),
                    MultipleTrusteeOperation: 0,
                    TrusteeForm: TRUSTEE_IS_SID,
                    TrusteeType: TRUSTEE_IS_USER,
                    ptstrName: launcher_sid.cast(),
                },
            },
        ];
        let mut new_acl: *mut ACL = std::ptr::null_mut();
        // SAFETY: two EXPLICIT_ACCESS entries in a live array; both trustee SIDs
        // outlive the call (`container_sid` owned by the caller, `launcher_sid`
        // pinned by `launcher_sid_buf`). `SetEntriesInAclW` allocates `new_acl`
        // (freed via LocalFree below). A null existing ACL means "start fresh".
        let err = unsafe {
            SetEntriesInAclW(
                2,
                entries.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::from_mut(&mut new_acl),
            )
        };
        if err != 0 || new_acl.is_null() {
            return Err(spawn(format!(
                "SetEntriesInAclW failed for {} (error = {err}); refusing to run without an \
                 enforced filesystem boundary",
                path.display()
            )));
        }
        let wpath = wide(path.as_os_str());
        // SAFETY: `wpath` is a live NUL-terminated wide path; `new_acl` is the ACL
        // just built; only the DACL is set. SE_FILE_OBJECT = 1.
        let status = unsafe {
            SetNamedSecurityInfoW(
                wpath.as_ptr(),
                1, // SE_FILE_OBJECT
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                new_acl,
                std::ptr::null_mut(),
            )
        };
        // Free the ACL regardless of outcome.
        // SAFETY: `new_acl` was allocated by SetEntriesInAclW; LocalFree releases it.
        unsafe {
            LocalFree(new_acl.cast());
        }
        if status != 0 {
            return Err(spawn(format!(
                "SetNamedSecurityInfoW failed for {} (status = {status}); refusing to run without \
                 an enforced filesystem boundary",
                path.display()
            )));
        }
        Ok(())
    }

    /// Grant `FILE_TRAVERSE` to the AppContainer SID on every ancestor directory
    /// of `path` up to (but not including) the volume root.
    ///
    /// `CreateProcessW` resolves `lpCurrentDirectory` by walking every path
    /// component through the AppContainer token. If any ancestor directory does
    /// not have `FILE_TRAVERSE` granted to the container SID, the walk stops and
    /// the child cannot start there. ACLing the scratch directory itself (done by
    /// `acl_path_for_container`) is therefore not enough: every ancestor up to the
    /// volume root must also allow the container SID to traverse it.
    ///
    /// The grant is additive: the function merges a single `GRANT_ACCESS`
    /// `FILE_TRAVERSE` entry into the existing DACL of each ancestor via
    /// `SetEntriesInAclW` with a non-null existing ACL, preserving every other
    /// entry. This never removes or narrows any existing permission. Fail-closed:
    /// any failed Win32 call refuses so the caller never proceeds with an
    /// incompletely granted ancestor chain.
    #[allow(unsafe_code)]
    // IPE-RUST-AUDIT:ACCEPTED — Win32 FFI that no vetted safe crate wraps; SAFETY per block.
    fn grant_traverse_to_ancestors(path: &Path, container_sid: PSID) -> Result<(), RunJailDefect> {
        use windows_sys::Win32::Security::Authorization::{GRANT_ACCESS, GetNamedSecurityInfoW};

        // Resolve the volume root so we know when to stop walking.
        const MAX_PATH_WCHARS: u32 = 260;
        let wpath = wide(path.as_os_str());
        let mut root_buf: Vec<u16> = vec![0u16; MAX_PATH_WCHARS as usize];
        // SAFETY: `wpath` is a live NUL-terminated wide path; `root_buf` receives
        // the volume mount-point (e.g. "C:\") NUL-terminated into a MAX_PATH buffer.
        let got_root =
            unsafe { GetVolumePathNameW(wpath.as_ptr(), root_buf.as_mut_ptr(), MAX_PATH_WCHARS) };
        if got_root == 0 {
            return Err(last_error_spawn(&format!(
                "GetVolumePathNameW failed for {} while granting ancestor traversal; refusing",
                path.display()
            )));
        }
        // Trim to the actual NUL-terminated string length for comparison.
        let root_len = root_buf
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(root_buf.len());
        let volume_root: Vec<u16> = root_buf[..root_len].to_vec();

        // Walk from `path`'s parent up toward (but not including) the volume root.
        let mut current = path.to_path_buf();
        loop {
            current = match current.parent() {
                Some(p) => p.to_path_buf(),
                None => break,
            };
            // Stop at the volume root — it already allows traversal to everyone.
            let wcurrent = wide(current.as_os_str());
            let current_len = wcurrent.len().saturating_sub(1); // exclude NUL
            if current_len == volume_root.len()
                && wcurrent[..current_len]
                    .iter()
                    .zip(&volume_root)
                    .all(|(a, b)| {
                        // `u16` has no `to_ascii_uppercase`; fold through `u8` for the
                        // ASCII range (volume roots are always ASCII, e.g. "C:\").
                        let au = if *a < 0x80 {
                            (*a as u8).to_ascii_uppercase() as u16
                        } else {
                            *a
                        };
                        let bu = if *b < 0x80 {
                            (*b as u8).to_ascii_uppercase() as u16
                        } else {
                            *b
                        };
                        au == bu
                    })
            {
                break;
            }

            // Fetch the existing DACL via GetNamedSecurityInfoW so we can merge
            // into it (GRANT_ACCESS preserves existing entries).
            let mut existing_dacl: *mut ACL = std::ptr::null_mut();
            // GetNamedSecurityInfoW writes a PSECURITY_DESCRIPTOR (*mut c_void)
            // here; LocalFree releases it when we are done. The DACL pointer
            // (`existing_dacl`) points into this allocation and is valid until
            // `sd_ptr` is freed.
            let mut sd_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
            // SAFETY: `wcurrent` is a live NUL-terminated wide path; the call
            // allocates the security descriptor into `sd_ptr` (freed via
            // LocalFree below) and sets `existing_dacl` as a pointer into it.
            // Only the DACL is requested; other out-params receive null.
            let get_err = unsafe {
                GetNamedSecurityInfoW(
                    wcurrent.as_ptr(),
                    1, // SE_FILE_OBJECT
                    DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &raw mut existing_dacl,
                    std::ptr::null_mut(),
                    &raw mut sd_ptr,
                )
            };
            if get_err != 0 {
                // Free the security descriptor even on error if it was partially
                // allocated, then fail closed.
                if !sd_ptr.is_null() {
                    // SAFETY: `sd_ptr` was allocated by GetNamedSecurityInfoW.
                    unsafe { LocalFree(sd_ptr.cast()) };
                }
                return Err(spawn(format!(
                    "GetNamedSecurityInfoW failed for {} (error = {get_err}) while granting \
                     ancestor traversal; refusing",
                    current.display()
                )));
            }

            // Merge a GRANT_ACCESS FILE_TRAVERSE entry into the existing DACL.
            let entry = EXPLICIT_ACCESS_W {
                grfAccessPermissions: FILE_TRAVERSE,
                grfAccessMode: GRANT_ACCESS,
                grfInheritance: NO_INHERITANCE,
                Trustee: TRUSTEE_W {
                    pMultipleTrustee: std::ptr::null_mut(),
                    MultipleTrusteeOperation: 0,
                    TrusteeForm: TRUSTEE_IS_SID,
                    TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                    ptstrName: container_sid.cast(),
                },
            };
            let entries = [entry];
            let mut new_acl: *mut ACL = std::ptr::null_mut();
            // SAFETY: one EXPLICIT_ACCESS entry in a live array; `container_sid`
            // outlives this call (owned by the caller); `existing_dacl` points into
            // `sd_ptr` which is still live. `SetEntriesInAclW` allocates `new_acl`
            // (freed via LocalFree below).
            let acl_err = unsafe {
                SetEntriesInAclW(
                    1,
                    entries.as_ptr(),
                    existing_dacl,
                    std::ptr::from_mut(&mut new_acl),
                )
            };
            // Release the security descriptor from GetNamedSecurityInfoW.
            if !sd_ptr.is_null() {
                // SAFETY: allocated by GetNamedSecurityInfoW.
                unsafe { LocalFree(sd_ptr.cast()) };
            }
            if acl_err != 0 || new_acl.is_null() {
                return Err(spawn(format!(
                    "SetEntriesInAclW failed for {} (error = {acl_err}) while granting ancestor \
                     traversal; refusing",
                    current.display()
                )));
            }

            // Apply the merged DACL.
            // SAFETY: `wcurrent` is a live NUL-terminated wide path; `new_acl` is
            // the ACL just built. Only the DACL is set.
            let set_err = unsafe {
                SetNamedSecurityInfoW(
                    wcurrent.as_ptr(),
                    1, // SE_FILE_OBJECT
                    DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    new_acl,
                    std::ptr::null_mut(),
                )
            };
            // Free the merged ACL regardless of outcome.
            // SAFETY: allocated by SetEntriesInAclW.
            unsafe { LocalFree(new_acl.cast()) };
            if set_err != 0 {
                return Err(spawn(format!(
                    "SetNamedSecurityInfoW failed for {} (status = {set_err}) while granting \
                     ancestor traversal; refusing",
                    current.display()
                )));
            }
        }
        Ok(())
    }

    /// Query the launcher process's own user SID into an owned buffer. The
    /// returned `Vec<u64>` holds a `TOKEN_USER` whose `User.Sid` points back into
    /// the same allocation, so the buffer must outlive every use of that pointer.
    /// `u64` elements give the allocation 8-byte alignment, which `TOKEN_USER`
    /// (containing a pointer) requires. Fail-closed: any failed Win32 call refuses.
    #[allow(unsafe_code)]
    // IPE-RUST-AUDIT:ACCEPTED — Win32 FFI that no vetted safe crate wraps; SAFETY per block.
    fn launcher_user_sid_buffer() -> Result<Vec<u64>, RunJailDefect> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: `GetCurrentProcess` is a pseudo-handle (never closed); we request
        // TOKEN_QUERY and receive an owned token handle in `token`.
        let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) };
        if opened == 0 || token.is_null() {
            return Err(last_error_spawn(
                "OpenProcessToken failed for the launcher token",
            ));
        }
        let token = OwnedHandle(token);
        // First call: learn the required buffer length (expected to fail with
        // ERROR_INSUFFICIENT_BUFFER while writing `needed`).
        let mut needed: u32 = 0;
        // SAFETY: null buffer with zero length is the documented size-probe form;
        // `needed` receives the byte count.
        unsafe {
            GetTokenInformation(
                token.get(),
                TokenUser,
                std::ptr::null_mut(),
                0,
                &raw mut needed,
            );
        }
        if needed == 0 {
            return Err(last_error_spawn(
                "GetTokenInformation size probe reported zero length for the launcher token",
            ));
        }
        // Round the byte count up to whole `u64` words so the allocation is both
        // large enough and 8-byte aligned.
        let words = (needed as usize).div_ceil(std::mem::size_of::<u64>());
        let mut buffer: Vec<u64> = vec![0u64; words];
        let mut written: u32 = 0;
        // SAFETY: `buffer` is at least `needed` bytes and 8-byte aligned;
        // `GetTokenInformation` fills a `TOKEN_USER` (its embedded SID points
        // within the same allocation).
        let ok = unsafe {
            GetTokenInformation(
                token.get(),
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &raw mut written,
            )
        };
        if ok == 0 {
            return Err(last_error_spawn(
                "GetTokenInformation failed to read the launcher user SID",
            ));
        }
        Ok(buffer)
    }

    /// Establish, at the boundary, that `path` lives on a volume whose filesystem
    /// persists and enforces DACLs (`FILE_PERSISTENT_ACLS`) — the precondition the
    /// ACL-mediated [`acl_path_for_container`] boundary silently depends on.
    ///
    /// On a volume WITHOUT that bit (FAT/exFAT — a USB stick, a redirected
    /// `%TEMP%`, some network shares), `SetNamedSecurityInfoW` returns success
    /// while persisting/enforcing NOTHING, so the ACL would be a no-op and the
    /// sandboxed app would run with the filesystem UNCONFINED even though the admit
    /// path already trusted it. Probe once with `GetVolumeInformationW`, parse the
    /// flags through the pure [`crate::run_jail::volume_flags_confine_filesystem`], and refuse
    /// (fail closed) when the bit is absent. Any probe failure also refuses.
    #[allow(unsafe_code)]
    // IPE-RUST-AUDIT:ACCEPTED — Win32 FFI that no vetted safe crate wraps; SAFETY per block.
    fn probe_volume_persists_acls(path: &Path) -> Result<(), RunJailDefect> {
        const MAX_PATH_WCHARS: u32 = 260;
        // `GetVolumeInformationW` needs a volume root, not an arbitrary path;
        // resolve the mount point of `path` first.
        let wpath = wide(path.as_os_str());
        let mut root: Vec<u16> = vec![0u16; MAX_PATH_WCHARS as usize];
        // SAFETY: `wpath` is a live NUL-terminated wide path; `root` is a
        // `MAX_PATH_WCHARS`-element buffer receiving the NUL-terminated volume
        // mount point.
        let got_root =
            unsafe { GetVolumePathNameW(wpath.as_ptr(), root.as_mut_ptr(), MAX_PATH_WCHARS) };
        if got_root == 0 {
            return Err(last_error_spawn(&format!(
                "GetVolumePathNameW failed for {}; refusing to run without proving the volume \
                 persists ACLs",
                path.display()
            )));
        }
        let mut fs_flags: u32 = 0;
        // SAFETY: `root` is a live NUL-terminated wide root path; we pass null for
        // the name/serial/component outputs we do not need and a live `fs_flags`
        // out-param; no volume/filesystem name buffers are requested.
        let got_info = unsafe {
            GetVolumeInformationW(
                root.as_ptr(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &raw mut fs_flags,
                std::ptr::null_mut(),
                0,
            )
        };
        if got_info == 0 {
            return Err(last_error_spawn(&format!(
                "GetVolumeInformationW failed for {}; refusing to run without proving the volume \
                 persists ACLs",
                path.display()
            )));
        }
        if crate::run_jail::volume_flags_confine_filesystem(fs_flags) {
            Ok(())
        } else {
            Err(spawn(format!(
                "the volume backing {} lacks FILE_PERSISTENT_ACLS (flags = {fs_flags:#x}); its \
                 ACLs are not enforced, so the filesystem boundary would be a no-op — refusing to \
                 run",
                path.display()
            )))
        }
    }

    /// The scrubbed environment as a doubly-NUL-terminated UTF-16 block for
    /// `CreateProcess` `lpEnvironment` (with `CREATE_UNICODE_ENVIRONMENT`).
    fn env_block_utf16(
        profile: &SandboxProfile,
        scoped_tmp: &Path,
        host_env: &dyn Fn(&str) -> Option<OsString>,
    ) -> Vec<u16> {
        // The scrub + the block layout (sorted, doubly-NUL-terminated, no empty-name
        // entries) is one host-independent source: `windows_scrubbed_env` +
        // `env_block_from_pairs`. Unit tests on any host assert the exact bytes this
        // hands to `CreateProcessW`, so the arm cannot drift from what is proven.
        super::env_block_from_pairs(&windows_scrubbed_env(profile, scoped_tmp, host_env))
    }

    /// The created child's owned process + thread handles.
    struct Child {
        process: OwnedHandle,
        thread: OwnedHandle,
    }

    /// CreateProcess suspended with the AppContainer security-capabilities
    /// attribute and the scrubbed environment. The command line is built from the
    /// app path + args with proper quoting; there is no shell.
    ///
    /// `current_dir` is the child's `lpCurrentDirectory`. It MUST be a directory the
    /// AppContainer token can access — otherwise `CreateProcessW` cannot resolve
    /// the current directory for the child. The caller passes the always-ACLed
    /// scratch (never the working tree, which is unreachable to the container when
    /// the filesystem axis is withheld).
    /// The CWD is not a capability: the child can still reach only what is ACLed to
    /// the container SID, so pointing it at the scratch neither grants nor widens
    /// any axis.
    #[allow(unsafe_code)]
    // IPE-RUST-AUDIT:ACCEPTED — Win32 FFI that no vetted safe crate wraps; SAFETY per block.
    fn create_suspended_appcontainer_process(
        app: &Path,
        app_args: &[OsString],
        current_dir: &Path,
        container: &AppContainer,
        capabilities: &mut CapabilitySids,
        env_block: &[u16],
    ) -> Result<Child, RunJailDefect> {
        // The attribute list carrying the security-capabilities (AppContainer)
        // attribute.
        let mut attr_size: usize = 0;
        // SAFETY: first call with a null list and a zeroed size queries the required
        // size (documented pattern); it returns 0 with ERROR_INSUFFICIENT_BUFFER.
        unsafe {
            InitializeProcThreadAttributeList(
                std::ptr::null_mut(),
                1,
                0,
                std::ptr::from_mut(&mut attr_size),
            );
        }
        if attr_size == 0 {
            return Err(spawn("InitializeProcThreadAttributeList sizing failed"));
        }
        let mut attr_buf: Vec<u8> = vec![0u8; attr_size];
        let attr_list = attr_buf.as_mut_ptr().cast();
        // SAFETY: `attr_buf` is `attr_size` bytes; initialises the list for 1 attr.
        let ok = unsafe {
            InitializeProcThreadAttributeList(attr_list, 1, 0, std::ptr::from_mut(&mut attr_size))
        };
        if ok == 0 {
            return Err(last_error_spawn("InitializeProcThreadAttributeList failed"));
        }
        // The list must be deleted on every path once initialised.
        let _attr_guard = AttrListGuard(attr_list);

        let mut sec_caps = capabilities.security_capabilities(container.sid());
        // SAFETY: `attr_list` is initialised; `sec_caps` is a live struct that
        // outlives the CreateProcess call (kept in this scope), pointed at by the
        // attribute. The size is that struct's size.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                std::ptr::from_mut(&mut sec_caps).cast(),
                std::mem::size_of::<SECURITY_CAPABILITIES>(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(last_error_spawn("UpdateProcThreadAttribute failed"));
        }

        let mut si = STARTUPINFOEXW {
            StartupInfo: STARTUPINFOW {
                cb: size_u32::<STARTUPINFOEXW>(),
                ..STARTUPINFOW::default()
            },
            lpAttributeList: attr_list,
        };

        let mut cmdline = build_command_line(app, app_args);
        let mut wdir = wide(current_dir.as_os_str());
        // The env block is `*const c_void` (cast from the u16 slice).
        let env_ptr = env_block.as_ptr().cast::<std::ffi::c_void>().cast_mut();

        let mut pi = PROCESS_INFORMATION::default();
        // SAFETY: `cmdline` is a mutable NUL-terminated wide buffer (CreateProcessW
        // may write to it); `env_ptr` is the doubly-NUL wide env block;
        // `wdir` is a live wide path; `si` carries the initialised attribute list;
        // `pi` receives the process/thread handles. CREATE_SUSPENDED so the child
        // does not run before it is assigned to the job.
        let ok = unsafe {
            CreateProcessW(
                std::ptr::null(),
                cmdline.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0, // do not inherit handles
                CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                env_ptr,
                wdir.as_mut_ptr(),
                std::ptr::from_mut(&mut si).cast(),
                std::ptr::from_mut(&mut pi),
            )
        };
        if ok == 0 {
            return Err(last_error_spawn("CreateProcessW (AppContainer) failed"));
        }
        Ok(Child {
            process: OwnedHandle(pi.hProcess),
            thread: OwnedHandle(pi.hThread),
        })
    }

    /// A proc-thread attribute list deleted on drop.
    struct AttrListGuard(*mut std::ffi::c_void);

    impl Drop for AttrListGuard {
        #[allow(unsafe_code)]
        // IPE-RUST-AUDIT:ACCEPTED — Win32 FFI that no vetted safe crate wraps; SAFETY per block.
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` is an initialised attribute list this guard owns.
                unsafe {
                    DeleteProcThreadAttributeList(self.0);
                }
            }
        }
    }

    /// Build the child command line: the app path plus each arg, each token quoted
    /// per the Win32 command-line convention. There is NO shell — this is the
    /// argument vector CreateProcess parses, so the shell-injection class does not
    /// exist.
    fn build_command_line(app: &Path, app_args: &[OsString]) -> Vec<u16> {
        let mut s = OsString::new();
        push_quoted(&mut s, app.as_os_str());
        for arg in app_args {
            s.push(OsStr::new(" "));
            push_quoted(&mut s, arg);
        }
        wide(&s)
    }

    /// Append `arg` to `out` quoted per the CommandLineToArgvW rules (wrap in
    /// double quotes, backslash-escape embedded quotes and trailing backslashes).
    fn push_quoted(out: &mut OsString, arg: &OsStr) {
        out.push(OsStr::new("\""));
        let text = arg.to_string_lossy();
        let mut backslashes = 0usize;
        let mut escaped = String::new();
        for ch in text.chars() {
            match ch {
                '\\' => {
                    backslashes += 1;
                    escaped.push('\\');
                }
                '"' => {
                    // Double the run of backslashes preceding a quote, then escape
                    // the quote itself.
                    for _ in 0..backslashes {
                        escaped.push('\\');
                    }
                    backslashes = 0;
                    escaped.push('\\');
                    escaped.push('"');
                }
                other => {
                    backslashes = 0;
                    escaped.push(other);
                }
            }
        }
        // Double a trailing backslash run so the closing quote is not escaped.
        for _ in 0..backslashes {
            escaped.push('\\');
        }
        out.push(OsStr::new(&escaped));
        out.push(OsStr::new("\""));
    }

    /// Assign the live suspended `process` to `job` before it resumes: the
    /// documented no-un-jobbed-instruction order.
    fn assign_to_job(job: &win32job::Job, process: HANDLE) -> Result<(), RunJailDefect> {
        job.assign_process(isize::from_ne_bytes(
            process.expose_provenance().to_ne_bytes(),
        ))
        .map_err(|e| {
            spawn(format!(
                "AssignProcessToJobObject failed: {}",
                std::io::Error::from(e)
            ))
        })
    }

    #[allow(unsafe_code)]
    // IPE-RUST-AUDIT:ACCEPTED — Win32 FFI that no vetted safe crate wraps; SAFETY per block.
    fn resume(thread: HANDLE) -> Result<(), RunJailDefect> {
        // SAFETY: `thread` is the live suspended main thread handle owned by the
        // caller; resuming it starts the (now jobbed, tokened) child.
        let prev = unsafe { ResumeThread(thread) };
        if prev == u32::MAX {
            return Err(last_error_spawn("ResumeThread failed"));
        }
        Ok(())
    }

    /// Wait for the child and read its exit code. The job handle must stay open in
    /// the caller across this wait so KILL_ON_JOB_CLOSE holds for the child's life.
    #[allow(unsafe_code)]
    // IPE-RUST-AUDIT:ACCEPTED — Win32 FFI that no vetted safe crate wraps; SAFETY per block.
    fn wait_and_exit_code(process: HANDLE) -> Result<u32, RunJailDefect> {
        // SAFETY: `process` is a live handle owned by the caller; an infinite wait
        // blocks until the child exits.
        let w = unsafe { WaitForSingleObject(process, u32::MAX) };
        if w != WAIT_OBJECT_0 {
            return Err(last_error_spawn(
                "WaitForSingleObject on the jailed child failed",
            ));
        }
        let mut code: u32 = 0;
        // SAFETY: `process` is a live handle; `code` receives the exit code.
        let ok = unsafe { GetExitCodeProcess(process, std::ptr::from_mut(&mut code)) };
        if ok == 0 {
            return Err(last_error_spawn("GetExitCodeProcess failed"));
        }
        Ok(code)
    }

    /// The Job Object active-process cap for a profile: 1 when subprocess is
    /// withheld (only the app itself), else the profile's proc cap (min 1).
    /// Extracted so the cap policy is unit-testable without a live Job Object.
    fn active_process_cap(profile: &SandboxProfile) -> u32 {
        if profile.subprocess {
            u32::try_from(profile.limits.proc_cap)
                .unwrap_or(u32::MAX)
                .max(1)
        } else {
            1
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::run_jail::{RunResourceLimits, SandboxProfile};

        fn profile_with_env(names: &[&str]) -> SandboxProfile {
            SandboxProfile {
                env_allowlist: names.iter().map(|s| (*s).to_owned()).collect(),
                ..SandboxProfile::maximally_isolated()
            }
        }

        #[test]
        fn env_block_utf16_matches_the_shared_host_independent_builder() {
            // The Windows arm's `env_block_utf16` is a thin wrapper: it must produce
            // exactly what the host-independent `windows_scrubbed_env` +
            // `env_block_from_pairs` (asserted by the outer module's tests on every
            // host) produce, so the bytes proven there are the bytes handed to
            // `CreateProcessW`. This guards the SSOT on Windows too — a wide-string
            // divergence (a non-UTF-8 path unit) would surface as a byte mismatch.
            let profile = profile_with_env(&["ALLOWED"]);
            let host = |k: &str| match k {
                "ALLOWED" => Some(OsString::from("yes")),
                "SECRET" => Some(OsString::from("leak")),
                "SystemRoot" => Some(OsString::from("C:\\Windows")),
                _ => None,
            };
            let via_arm = env_block_utf16(&profile, Path::new("C:\\scratch"), &host);
            let via_shared = super::super::env_block_from_pairs(&windows_scrubbed_env(
                &profile,
                Path::new("C:\\scratch"),
                &host,
            ));
            assert_eq!(
                via_arm, via_shared,
                "arm must not drift from the SSOT block"
            );
        }

        #[test]
        fn command_line_quotes_each_arg_and_has_no_shell() {
            let cmd = build_command_line(
                Path::new("C:\\apps\\my app.exe"),
                &[OsString::from("plain"), OsString::from("has space")],
            );
            let s = String::from_utf16_lossy(&cmd);
            // The app path with a space is quoted.
            assert!(s.starts_with("\"C:\\apps\\my app.exe\""), "{s:?}");
            assert!(s.contains("\"plain\""), "{s:?}");
            assert!(s.contains("\"has space\""), "{s:?}");
            // No shell metacharacters are interpreted — it is a direct argv.
            assert!(!s.contains("cmd.exe"), "{s:?}");
            assert!(!s.contains(" /c "), "{s:?}");
        }

        #[test]
        fn embedded_quotes_are_escaped() {
            let mut out = OsString::new();
            push_quoted(&mut out, OsStr::new("a\"b"));
            let s = out.to_string_lossy();
            assert_eq!(s, "\"a\\\"b\"", "{s:?}");
        }

        #[test]
        fn active_process_cap_is_one_when_subprocess_withheld() {
            // A pure profile (subprocess absent) must cap the job at 1 process, so
            // no child can spawn.
            let withheld = SandboxProfile::maximally_isolated();
            assert!(!withheld.subprocess);
            let granted = SandboxProfile {
                subprocess: true,
                limits: RunResourceLimits {
                    proc_cap: 8,
                    ..RunResourceLimits::default()
                },
                ..SandboxProfile::maximally_isolated()
            };
            assert_eq!(active_process_cap(&withheld), 1);
            assert_eq!(active_process_cap(&granted), 8);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{OsStr, OsString};
    use std::path::Path;

    fn env_profile(names: &[&str]) -> SandboxProfile {
        SandboxProfile {
            env_allowlist: names.iter().map(|n| (*n).to_owned()).collect(),
            ..SandboxProfile::maximally_isolated()
        }
    }

    /// Decode the block into its `NAME=VALUE` entries (split on the NUL separators,
    /// dropping the terminating empties), for order/content assertions.
    fn decode_block(block: &[u16]) -> Vec<String> {
        String::from_utf16_lossy(block)
            .split('\0')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn env_block_is_doubly_nul_terminated_and_scrubs_non_allowlisted() {
        let profile = env_profile(&["ALLOWED"]);
        let host = |k: &str| match k {
            "ALLOWED" => Some(OsString::from("yes")),
            "SECRET" => Some(OsString::from("leak")),
            "SystemRoot" => Some(OsString::from("C:\\Windows")),
            _ => None,
        };
        let pairs = windows_scrubbed_env(&profile, Path::new("C:\\scratch"), &host);
        let block = env_block_from_pairs(&pairs);
        // Doubly-NUL terminated: the last entry's own NUL plus the block terminator.
        assert!(
            block.ends_with(&[0, 0]),
            "must be doubly-NUL-terminated (\\0\\0)"
        );
        let entries = decode_block(&block);
        assert!(
            entries.iter().any(|e| e == "ALLOWED=yes"),
            "allowlisted var survives: {entries:?}"
        );
        // A non-allowlisted host var must NOT reach the child.
        assert!(
            !entries
                .iter()
                .any(|e| e.contains("SECRET") || e.contains("leak")),
            "non-allowlisted var must be scrubbed: {entries:?}"
        );
        // The required AppContainer base is present.
        assert!(
            entries.iter().any(|e| e.starts_with("SystemRoot=")),
            "SystemRoot must be present for AppContainer: {entries:?}"
        );
    }

    #[test]
    fn env_block_names_are_sorted_in_windows_uppercase_ordinal_order() {
        // `_` (0x5F) sorts AFTER the letters under Windows' uppercase-ordinal
        // collation (`A`..=`Z` = 0x41..=0x5A) but BEFORE them if the block were
        // lowercased (`a`..=`z` = 0x61..=0x7A). `APP_KEY` vs `APPLE` distinguishes
        // the two orders: correct Windows order is `APPLE` before `APP_KEY`.
        let profile = env_profile(&["APP_KEY", "APPLE", "zeta"]);
        let host = |k: &str| match k {
            "APP_KEY" | "APPLE" | "zeta" => Some(OsString::from("v")),
            "SystemRoot" => Some(OsString::from("C:\\Windows")),
            _ => None,
        };
        let pairs = windows_scrubbed_env(&profile, Path::new("C:\\scratch"), &host);
        let names: Vec<String> = pairs
            .iter()
            .map(|(n, _)| n.to_string_lossy().into_owned())
            .collect();
        let apple = names.iter().position(|n| n == "APPLE");
        let app_key = names.iter().position(|n| n == "APP_KEY");
        assert!(
            apple < app_key,
            "uppercase-ordinal order puts APPLE before APP_KEY (got {names:?})"
        );
        // The whole block is sorted on the uppercase-ordinal key.
        let keys: Vec<String> = pairs
            .iter()
            .map(|(n, _)| env_name_collation_key(n))
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(
            keys, sorted,
            "block must be name-sorted (uppercase ordinal)"
        );
    }

    #[test]
    fn env_block_has_no_empty_name_entry_even_when_an_empty_name_is_granted() {
        // An empty allowlist name can never form a valid `NAME=VALUE`; Windows rejects
        // a block containing one. Even if a profile carries an empty name it must be
        // dropped fail-closed, never emitted as a `=VALUE` entry.
        let profile = env_profile(&["", "REAL"]);
        let host = |k: &str| match k {
            "" => Some(OsString::from("wat")),
            "REAL" => Some(OsString::from("ok")),
            "SystemRoot" => Some(OsString::from("C:\\Windows")),
            _ => None,
        };
        let pairs = windows_scrubbed_env(&profile, Path::new("C:\\scratch"), &host);
        let block = env_block_from_pairs(&pairs);
        for entry in decode_block(&block) {
            assert!(
                !entry.starts_with('='),
                "no entry may have an empty name: {entry:?}"
            );
            assert!(
                entry.contains('='),
                "every entry is a NAME=VALUE pair: {entry:?}"
            );
        }
        assert!(
            decode_block(&block).iter().any(|e| e == "REAL=ok"),
            "the non-empty allowlisted var still survives"
        );
    }

    #[test]
    fn empty_pairs_still_yield_a_valid_empty_block() {
        // No pairs → a lone `\0\0`, the valid empty environment `CreateProcess`
        // expects (never a single NUL it would read past).
        let block = env_block_from_pairs(&[]);
        assert_eq!(block, vec![0u16, 0u16]);
    }

    #[test]
    fn an_allowlisted_name_colliding_case_insensitively_with_a_base_is_deduped() {
        // Windows environments are case-insensitive: a block holding two names that
        // fold to the same key is malformed. A profile can grant a name
        // that collides with a fixed base (`SystemRoot`), so the collision must
        // collapse to ONE entry — the base value, never the allowlist re-grant's.
        let profile = env_profile(&["systemroot"]);
        let host = |k: &str| match k {
            "SystemRoot" => Some(OsString::from("C:\\Windows")),
            "systemroot" => Some(OsString::from("C:\\Attacker")),
            _ => None,
        };
        let pairs = windows_scrubbed_env(&profile, Path::new("C:\\scratch"), &host);
        let system_roots: Vec<&OsString> = pairs
            .iter()
            .filter(|(n, _)| env_name_collation_key(n) == "SYSTEMROOT")
            .map(|(_, value)| value)
            .collect();
        assert_eq!(
            system_roots,
            vec![&OsString::from("C:\\Windows")],
            "a case-insensitive collision collapses to one entry, base value winning: {pairs:?}"
        );
    }

    #[test]
    fn a_value_containing_an_equals_sign_is_preserved_whole() {
        // A `=` in a VALUE is not a separator: Windows splits a block entry on the
        // FIRST `=`, so `NAME=a=b` is name `NAME`, value `a=b`. The builder must not
        // mangle it.
        let profile = env_profile(&["CONN"]);
        let host = |k: &str| match k {
            "CONN" => Some(OsString::from("k=v;x=y")),
            "SystemRoot" => Some(OsString::from("C:\\Windows")),
            _ => None,
        };
        let block = env_block_from_pairs(&windows_scrubbed_env(
            &profile,
            Path::new("C:\\scratch"),
            &host,
        ));
        assert!(
            decode_block(&block).iter().any(|e| e == "CONN=k=v;x=y"),
            "a `=` inside a value must survive whole: {:?}",
            decode_block(&block)
        );
    }

    /// The `AppContainer` profile variables `CreateProcessW` reads from the block.
    const PROFILE_VARS: [&str; 5] = [
        "LOCALAPPDATA",
        "APPDATA",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
    ];

    /// A host that sets every base name, the profile variables, and one secret.
    fn full_host(name: &str) -> Option<OsString> {
        match name {
            "SystemRoot" => Some(OsString::from("C:\\Windows")),
            "PATH" => Some(OsString::from("C:\\Windows\\System32")),
            "LANG" => Some(OsString::from("C.UTF-8")),
            "LOCALAPPDATA" => Some(OsString::from("C:\\Users\\u\\AppData\\Local")),
            "APPDATA" => Some(OsString::from("C:\\Users\\u\\AppData\\Roaming")),
            "USERPROFILE" => Some(OsString::from("C:\\Users\\u")),
            "HOMEDRIVE" => Some(OsString::from("C:")),
            "HOMEPATH" => Some(OsString::from("\\Users\\u")),
            "ALLOWED" => Some(OsString::from("yes")),
            "SECRET" => Some(OsString::from("leak")),
            _ => None,
        }
    }

    fn value_of<'a>(pairs: &'a [(OsString, OsString)], name: &str) -> Option<&'a OsString> {
        pairs
            .iter()
            .find(|(n, _)| n.as_os_str() == OsStr::new(name))
            .map(|(_, v)| v)
    }

    #[test]
    fn windows_scrubbed_env_carries_the_appcontainer_profile_base() {
        let pairs = windows_scrubbed_env(&env_profile(&[]), Path::new("C:\\scratch"), &full_host);
        for name in PROFILE_VARS {
            assert_eq!(
                value_of(&pairs, name),
                full_host(name).as_ref(),
                "`{name}` must reach the child with the host value: {pairs:?}"
            );
        }
    }

    #[test]
    fn the_scrubbed_env_is_exactly_the_base_set_plus_the_allowlist() {
        let pairs = windows_scrubbed_env(
            &env_profile(&["ALLOWED"]),
            Path::new("C:\\scratch"),
            &full_host,
        );
        let mut got: Vec<&str> = pairs.iter().filter_map(|(n, _)| n.to_str()).collect();
        got.sort_unstable();
        let mut want: Vec<&str> = WindowsBaseEnv::ALL
            .into_iter()
            .map(WindowsBaseEnv::name)
            .chain(["ALLOWED"])
            .collect();
        want.sort_unstable();
        assert_eq!(got, want, "the child env is the declared set, nothing else");
        assert_eq!(
            value_of(&pairs, "TMP"),
            Some(&OsString::from("C:\\scratch")),
            "TMP is the scratch"
        );
        assert_eq!(
            value_of(&pairs, "TEMP"),
            Some(&OsString::from("C:\\scratch")),
            "TEMP is the scratch"
        );
    }

    #[test]
    fn a_profile_variable_the_host_leaves_unset_is_absent() {
        // No placeholder value is invented for a profile variable the host lacks.
        let host = |k: &str| match k {
            "SystemRoot" => Some(OsString::from("C:\\Windows")),
            _ => None,
        };
        let pairs = windows_scrubbed_env(&env_profile(&[]), Path::new("C:\\scratch"), &host);
        for name in PROFILE_VARS {
            assert_eq!(value_of(&pairs, name), None, "`{name}` must stay absent");
        }
    }

    #[test]
    fn a_granted_profile_variable_keeps_the_base_host_value() {
        // A profile re-grant of a base name never forms a second, colliding entry.
        let pairs = windows_scrubbed_env(
            &env_profile(&["userprofile"]),
            Path::new("C:\\scratch"),
            &|k: &str| match k {
                "userprofile" => Some(OsString::from("C:\\Elsewhere")),
                other => full_host(other),
            },
        );
        let hits: Vec<&OsString> = pairs
            .iter()
            .filter(|(n, _)| env_name_collation_key(n) == "USERPROFILE")
            .map(|(_, v)| v)
            .collect();
        assert_eq!(hits, vec![&OsString::from("C:\\Users\\u")]);
    }

    #[test]
    fn base_names_are_distinct_under_the_collation_key() {
        let mut keys: Vec<String> = WindowsBaseEnv::ALL
            .into_iter()
            .map(|base| env_name_collation_key(OsStr::new(base.name())))
            .collect();
        let total = keys.len();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), total, "two base names collide: {keys:?}");
    }

    #[test]
    #[allow(clippy::expect_used)] // test fixtures: the scratch dirs must exist
    fn windows_refuses_a_tree_with_vcs_metadata() {
        let base_dir = crate::test_dir::TestDir::new("windows-vcs").expect("test dir");
        let base = base_dir.path();
        let tree = base.join("tree");
        let tmp = base.join("tmp");
        std::fs::create_dir_all(tree.join(".hg")).expect("hg dir");
        std::fs::create_dir_all(&tmp).expect("tmp dir");
        let resolve = |path: &Path| crate::CanonicalPath::resolve(path).expect("canonical");
        let scratch = resolve(&tmp);
        let home = crate::Home::unknown();
        let writable = crate::WritableTree::parse(resolve(&tree), &[&scratch], &home)
            .expect("the tree parses");
        let planned = windows_working_tree_plan(&writable);
        assert!(
            matches!(
                &planned,
                Err(crate::JailPathError::VcsMetadataUncarvable {
                    arm: crate::JailArm::Windows,
                    path,
                }) if *path == tree.join(".hg")
            ),
            "{planned:?}"
        );
        std::fs::remove_dir(tree.join(".hg")).expect("remove hg dir");
        let plain = crate::WritableTree::parse(resolve(&tree), &[&scratch], &home)
            .expect("the tree parses");
        assert!(
            matches!(windows_working_tree_plan(&plain), Ok(path) if *path == resolve(&tree)),
            "a tree without metadata is granted"
        );
    }

    #[test]
    fn the_working_tree_grant_never_carries_delete_child() {
        const DELETE: u32 = 0x0001_0000;
        const FILE_DELETE_CHILD: u32 = 0x0000_0040;
        assert_eq!(WORKING_TREE_GRANT_MASK & DELETE, 0);
        assert_eq!(WORKING_TREE_GRANT_MASK & FILE_DELETE_CHILD, 0);
    }
}
