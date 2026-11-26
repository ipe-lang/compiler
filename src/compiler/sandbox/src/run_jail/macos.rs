//! The macOS run jail: the `sandbox-exec` (Seatbelt/SBPL) arms plus the
//! in-memory sealed-app delivery macOS uses in place of Linux's sealing memfd.
//! Compiled only on macOS; every other target gets the refuse stubs in
//! [`super`].

#![cfg(target_os = "macos")]

use std::ffi::OsString;
use std::path::Path;

use super::{RunJailDefect, RunJailTools, SandboxProfile};
use crate::host_tool::{self, HostTool, ToolPath};
use crate::{CanonicalPath, JailMounts};

/// macOS: probe for `sandbox-exec`, the run jail's only primitive.
///
/// The `bwrap`/`prlimit` tools the Linux jail needs do not apply; the
/// [`RunJailTools::Seatbelt`] arm carries the resolved `sandbox-exec`, which
/// [`exec_in_run_jail`] spawns. Fail-closed: an absent `sandbox-exec` refuses.
///
/// `_wants_wall_clock` is unused on macOS: the SBPL run jail carries no external
/// wall-clock helper.
///
/// # Errors
///
/// [`RunJailDefect::PrimitiveUnavailable`] when `sandbox-exec` is absent.
pub fn probe_run_jail_tools(_wants_wall_clock: bool) -> Result<RunJailTools, RunJailDefect> {
    let Ok(sandbox_exec) = host_tool::resolve(HostTool::SandboxExec) else {
        return Err(RunJailDefect::PrimitiveUnavailable {
            missing: vec![HostTool::SandboxExec.name()],
        });
    };
    Ok(RunJailTools::Seatbelt { sandbox_exec })
}

/// The `sandbox-exec` the tools carry; every other arm refuses.
fn seatbelt_of(tools: &RunJailTools) -> Result<&ToolPath, RunJailDefect> {
    match tools {
        RunJailTools::Seatbelt { sandbox_exec } => Ok(sandbox_exec),
        RunJailTools::Bwrap(_) | RunJailTools::Native => Err(RunJailDefect::PrimitiveUnavailable {
            missing: vec![HostTool::SandboxExec.name()],
        }),
    }
}

/// Run the emitted `app` binary inside the macOS `sandbox-exec` Seatbelt jail
/// described by `profile`, replacing the current process on success (Unix
/// `exec`).
///
/// The macOS counterpart to the `Linux` [`exec_in_run_jail`]: it lowers
/// the SAME [`SandboxProfile`] to a Seatbelt SBPL profile via the SAME
/// [`crate::build_jail::checked_sbpl`] the Tier-2 `build_in_jail` uses —
/// there is ONE SBPL generator, so what confines a Tier-2 build and what confines
/// the shipped app at run time cannot drift. It `exec`s
/// `sandbox-exec -p <profile> <app> <args>`: the profile travels in argv, never
/// through a file the app could rewrite. There is NO shell token anywhere — the payload is a direct argv, so the
/// quoting/injection class does not exist.
///
/// The SBPL enforces the network, filesystem, and subprocess axes; the `env` axis
/// is enforced HERE in the launcher (Seatbelt cannot scrub env): the environment
/// is cleared and only the profile's allowlisted names re-exported, via the SAME
/// [`crate::build_jail::macos_scrubbed_env`] the build jail and the e2e use — so
/// all four runtime-enforced axes are contained, matching the Linux jail, and the
/// FFI admit path's `Holds` verdict is honest on macOS.
///
/// `scoped_tmp` is the one always-writable scratch; `working_tree` is writable
/// only when the profile grants the filesystem axis. Both are checked against
/// the invoker's cargo home before the profile is lowered. Fail-closed: an
/// absent `sandbox-exec`, a path that does not resolve or would expose the cargo
/// home, or a failed `exec` REFUSES — the capability-bearing app is never run
/// unconfined.
///
/// The jail's actual deny behaviour is proven by the `macos-run-jail` CI job on a
/// real macOS runner; this crate builds the arm and unit-tests the pure SBPL
/// lowering on any host, but only a macOS runner exercises `sandbox-exec`.
///
/// # Errors
///
/// Any [`RunJailDefect`]; on success it does not return.
pub fn exec_in_run_jail(
    tools: &RunJailTools,
    profile: &SandboxProfile,
    scoped_tmp: &Path,
    working_tree: &Path,
    app: &Path,
    app_args: &[OsString],
) -> Result<std::convert::Infallible, RunJailDefect> {
    use std::os::unix::process::CommandExt as _;

    // `sandbox-exec` is the mandatory macOS jail primitive. Absent ⇒ refuse; the
    // capability-bearing app is never run unconfined.
    let sandbox_exec = seatbelt_of(tools)?;

    let mounts = JailMounts::of_invoker(
        CanonicalPath::resolve(scoped_tmp).map_err(RunJailDefect::Path)?,
        CanonicalPath::resolve(working_tree).map_err(RunJailDefect::Path)?,
        Vec::new(),
    )
    .map_err(RunJailDefect::Path)?;
    let scoped_tmp = mounts.scoped_tmp().as_path();

    // Lower the SAME profile through the SAME SBPL generator the build jail uses.
    let sbpl = crate::build_jail::checked_sbpl(profile, &mounts).map_err(RunJailDefect::Path)?;

    // argv: sandbox-exec -p <profile> <app> <app_args…>. Direct argv, no shell.
    let mut cmd = sandbox_exec.command();
    cmd.arg("-p").arg(&sbpl).arg(app).args(app_args);
    // Enforce the `env` axis in the launcher (Seatbelt cannot scrub env): clear
    // the inherited environment and re-export ONLY the scrubbed base plus the
    // profile's allowlisted names, mirroring the Linux jail's `--clearenv`. The
    // scrub is the SAME `macos_scrubbed_env` the e2e proves, so what confines the
    // env at run time and what the test asserts cannot drift.
    let host_env = crate::host_env::granted;
    cmd.env_clear();
    for (name, value) in crate::build_jail::macos_scrubbed_env(profile, scoped_tmp, &host_env) {
        cmd.env(name, value);
    }
    let err = cmd.exec();
    Err(RunJailDefect::Spawn {
        detail: err.to_string(),
    })
}

/// A verified embedded app binary held in memory.
///
/// macOS has no `memfd_create` and `sandbox-exec` cannot exec an inherited
/// descriptor, so the sealed-fd delivery the Linux arm uses is unavailable. The
/// bytes are held here after the single verification read; the exec arm writes
/// them ONCE to an exclusively-created (`O_EXCL`, mode 0700, unpredictably
/// named) file inside `scoped_tmp` and execs that. `scoped_tmp` is itself an
/// exclusively-created, unpredictable, owner-only directory, so no other path
/// exists to pre-seed or swap between the write and the exec.
pub struct SealedApp {
    bytes: Vec<u8>,
}

impl SealedApp {
    /// Read the app bytes for the capability-floor verification scan.
    #[must_use]
    pub fn read_sealed_bytes(&self) -> Result<Vec<u8>, RunJailDefect> {
        Ok(self.bytes.clone())
    }
}

/// Hold `bytes` for a later exclusive write-then-exec inside the jail scratch.
///
/// The Linux counterpart seals a memfd; macOS keeps the verified bytes in
/// memory because it has no sealing memfd and cannot fd-exec through
/// `sandbox-exec`.
///
/// # Errors
///
/// Infallible in practice; returns `Result` for arm-parity with the Linux
/// [`write_sealed_app_memfd`].
pub fn write_sealed_app_memfd(bytes: &[u8]) -> Result<SealedApp, RunJailDefect> {
    Ok(SealedApp {
        bytes: bytes.to_vec(),
    })
}

/// macOS embed-mode exec: write the verified bytes to an exclusively-created
/// file inside the exclusive `scoped_tmp` scratch and exec it under
/// `sandbox-exec`.
///
/// `sandbox-exec` cannot exec an inherited descriptor, so the same-inode
/// guarantee is delivered structurally instead: `scoped_tmp` is an
/// exclusively-created, unpredictable, owner-only directory, and the app file is
/// created with `O_EXCL` under a random name, so between the write and the exec
/// there is no predictable path an attacker can pre-seed or swap.
///
/// # Errors
///
/// Any [`RunJailDefect`]; on success it does not return.
pub fn exec_embedded_in_run_jail(
    tools: &RunJailTools,
    profile: &SandboxProfile,
    scoped_tmp: &Path,
    working_tree: &Path,
    app: &SealedApp,
    app_args: &[OsString],
) -> Result<std::convert::Infallible, RunJailDefect> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    // Exclusive-create the app file under the exclusive scratch dir. A random
    // name plus `create_new` (O_EXCL) means a pre-seeded entry fails rather than
    // being followed.
    let mut entropy = [0u8; 16];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut entropy))
        .is_err()
    {
        return Err(RunJailDefect::Spawn {
            detail: "could not read OS entropy for the embedded app path".to_owned(),
        });
    }
    let mut hex = String::with_capacity(32);
    for b in entropy {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    let app_path = scoped_tmp.join(format!("ipe-app-{hex}"));
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(&app_path)
    {
        Ok(f) => f,
        Err(e) => {
            return Err(RunJailDefect::Spawn {
                detail: format!("could not create the embedded app file: {e}"),
            });
        }
    };
    if let Err(e) = file.write_all(&app.bytes) {
        return Err(RunJailDefect::Spawn {
            detail: format!("could not write the embedded app file: {e}"),
        });
    }
    drop(file);

    exec_in_run_jail(
        tools,
        profile,
        scoped_tmp,
        working_tree,
        &app_path,
        app_args,
    )
}
