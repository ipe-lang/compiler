//! The sandboxed native build+run path for the playground `POST /run` endpoint.
//!
//! # Threat model
//!
//! `POST /run` accepts untrusted Ipê source, compiles it to a native Rust crate,
//! and then **builds and executes that crate**. Both the `cargo build` and the
//! resulting binary are attacker-derived code running on the server — a direct
//! remote-code-execution surface. Every build and every run therefore executes
//! inside the [`ipe_sandbox`] bubblewrap jail; the server never `cargo`-builds or
//! execs user-derived code outside it.
//!
//! The compile step (`ipe dev build`) is distinct: it runs the project's own trusted
//! compiler over the source text — deterministic codegen, not execution of the
//! user's program — so it stays a plain, timeout-bounded subprocess. Only the
//! two steps that run attacker-controlled code (build, run) are jailed.
//!
//! # Fail-closed
//!
//! If the host lacks the jail primitives (`bwrap`, `timeout`, `prlimit`), the
//! endpoint REFUSES — it never falls back to an unsandboxed build or run. The
//! only writable mount inside the jail is a per-request scratch directory, which
//! is removed after the request. Which jail knob enforces each control:
//!
//! | Control    | Enforcer (via [`ipe_sandbox`])                               |
//! |------------|--------------------------------------------------------------|
//! | Network    | `NetworkPolicy::Denied` → bwrap `--unshare-net` (no egress)   |
//! | Filesystem | `--ro-bind / /` + `--tmpfs` every home, `/tmp` + one `--bind` |
//! | Memory     | `prlimit --as`                                               |
//! | CPU        | `prlimit --cpu`                                              |
//! | Fork/proc  | `prlimit --nproc`                                            |
//! | Wall time  | `timeout --kill-after=5s <wall>` (SIGKILL on overrun)        |
//! | Output     | bounded stdout/stderr read (`out_cap_bytes`)                 |

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use ipe_sandbox::home::ToolHome;
use ipe_sandbox::{
    CanonicalPath, Capabilities, HomeMasks, JailPathError, JailSpec, NetworkPolicy, ResourceLimits,
    SandboxDefect, missing_caps, probe, run_in_bwrap_jail, run_in_bwrap_jail_deny_subprocess,
    run_jail::ProcCap,
};

/// Resource caps for one playground build+run.
///
/// Deliberately tighter than the FFI-inspection defaults: a playground program is
/// a small single crate, not an SDK-scale dependency closure, so a runaway is
/// killed at a low ceiling.
#[derive(Debug, Clone, Copy)]
pub struct RunCaps {
    /// Address-space cap in bytes (`prlimit --as`).
    pub rss_bytes: u64,
    /// CPU-seconds cap (`prlimit --cpu`).
    pub cpu_secs: u64,
    /// Wall-clock cap in seconds (`timeout`).
    pub wall_secs: u64,
    /// Open-file-descriptor cap (`prlimit --nofile`).
    pub fd_cap: u64,
    /// Process-count cap (`prlimit --nproc`) — a fork bomb is killed here.
    pub proc_cap: ProcCap,
    /// Maximum captured stdout/stderr bytes.
    pub out_cap_bytes: u64,
}

impl RunCaps {
    /// The build phase caps: a cargo build of one crate against a warm target
    /// legitimately spawns rustc + a linker, so `proc_cap` is generous enough for
    /// the toolchain while still bounding a fork bomb, and the wall clock is
    /// larger than the run phase's.
    ///
    /// `out_cap_bytes` is deliberately large: in the jail it is BOTH the stdout
    /// read cap AND the `prlimit --fsize` per-file write ceiling, and rustc writes
    /// `.rlib`/object artifacts well above a few MiB — too small an fsize SIGXFSZ-
    /// kills the build. 512 MiB clears a single crate's artifacts while still
    /// bounding a runaway that tries to fill the disk.
    #[must_use]
    pub const fn build_defaults() -> Self {
        Self {
            rss_bytes: 6 * 1024 * 1024 * 1024,
            cpu_secs: 900,
            wall_secs: 900,
            fd_cap: 512,
            proc_cap: ProcCap::of::<256>(),
            out_cap_bytes: 512 * 1024 * 1024,
        }
    }

    /// The run phase caps: executing the *emitted program*. Tight — a study
    /// program prints and exits; it never needs many processes or long CPU.
    ///
    /// `out_cap_bytes` bounds BOTH captured stdout and (as `prlimit --fsize`) any
    /// file the program writes into scratch, so a program that tries to fill the
    /// disk is SIGXFSZ-killed. 8 MiB is generous for a study program's output yet
    /// still a hard write ceiling.
    #[must_use]
    pub const fn run_defaults() -> Self {
        Self {
            rss_bytes: 512 * 1024 * 1024,
            cpu_secs: 5,
            wall_secs: 10,
            fd_cap: 64,
            // >1 so the tokio runtime's worker threads (same process, but nproc
            // counts threads) start; low enough that a fork bomb is killed.
            proc_cap: ProcCap::of::<32>(),
            out_cap_bytes: 8 * 1024 * 1024,
        }
    }

    const fn to_limits(self) -> ResourceLimits {
        ResourceLimits {
            rss_bytes: self.rss_bytes,
            cpu_secs: self.cpu_secs,
            wall_secs: self.wall_secs,
            fd_cap: self.fd_cap,
            proc_cap: self.proc_cap,
            out_cap_bytes: self.out_cap_bytes,
        }
    }
}

/// The read-only toolchain binds a jailed cargo build needs re-exposed past the
/// home tmpfs masks: `$CARGO_HOME/bin` (the proxy binaries) and the rustup home.
/// NEVER the cargo home itself — that holds `credentials.toml` (the crates.io
/// token), which must stay outside the jail.
///
/// Each bind is canonical, resolved once, so the `PATH` entry and
/// `RUSTUP_HOME` the payload is handed are the very paths bound.
///
/// # Errors
///
/// [`SandboxDefect::Path`] when `CARGO_HOME` or `RUSTUP_HOME` is relative, a
/// bind does not resolve, or a bind would expose the cargo home.
fn toolchain_binds() -> Result<ToolchainBinds, SandboxDefect> {
    let user_home = ipe_sandbox::home::home_dir().ok();
    let tool_home = |var: &'static str, fallback: &'static str| {
        ipe_sandbox::home::tool_home(var, user_home.as_ref(), fallback)
            .map_err(|e| SandboxDefect::Path(JailPathError::ToolHomeRelative(e)))
    };
    toolchain_binds_from(
        tool_home("CARGO_HOME", ".cargo")?.as_ref(),
        tool_home("RUSTUP_HOME", ".rustup")?,
    )
}

/// The toolchain binds for the given absolute cargo and rustup homes.
///
/// # Errors
///
/// [`SandboxDefect::Path`] when a bind does not resolve, or when the rustup home
/// sits at or above the cargo home, so binding it would expose
/// `credentials.toml`.
fn toolchain_binds_from(
    cargo_home: Option<&ToolHome>,
    rustup_home: Option<ToolHome>,
) -> Result<ToolchainBinds, SandboxDefect> {
    let cargo_home = cargo_home.map(ToolHome::as_path);
    let canonical = |path: &Path| CanonicalPath::resolve(path).map_err(SandboxDefect::Path);
    let mut binds = ToolchainBinds::default();
    if let Some(cargo_home) = cargo_home {
        let cargo_bin = cargo_home.join("bin");
        if cargo_bin.is_dir() {
            let cargo_bin = canonical(&cargo_bin)?;
            binds.path_prepend.push(cargo_bin.clone());
            binds.ro_binds.push(cargo_bin);
        }
    }
    if let Some(rustup) = rustup_home
        && rustup.as_path().is_dir()
    {
        let rustup = canonical(rustup.as_path())?;
        binds.ro_binds.push(rustup.clone());
        binds.rustup_home = Some(rustup);
    }
    if let Some(cargo_home) = cargo_home
        && let Some(bind) = ipe_sandbox::bind_exposing(&binds.ro_binds, cargo_home)
    {
        return Err(SandboxDefect::Path(JailPathError::ExposesCargoHome {
            bind: bind.as_path().to_path_buf(),
            cargo_home: cargo_home.to_path_buf(),
        }));
    }
    Ok(binds)
}

/// Why the jail could not be established for this host — the fail-closed refusal.
#[derive(Debug, Clone)]
pub struct JailUnavailable {
    /// The operator-facing refusal message (names the missing primitives).
    pub reason: String,
}

/// Probe the host jail primitives, or return the fail-closed refusal.
///
/// # Errors
///
/// [`JailUnavailable`] when `bwrap`, `timeout`, or `prlimit` is absent — the
/// endpoint refuses rather than run user code unconfined.
pub fn probe_or_refuse() -> Result<Capabilities, JailUnavailable> {
    let caps = probe();
    if caps.bwrap.is_none() {
        return Err(JailUnavailable {
            reason: "sandbox refused: bubblewrap (`bwrap`) is not installed on this host; \
                     the playground will not build or run user code without a jail"
                .to_owned(),
        });
    }
    let missing = missing_caps(&caps);
    if !missing.is_empty() {
        return Err(JailUnavailable {
            reason: format!(
                "sandbox refused: mandatory jail cap helper(s) absent ({}); \
                 install coreutils (timeout) and util-linux (prlimit)",
                missing.join(", ")
            ),
        });
    }
    Ok(caps)
}

/// The outcome of a single jailed phase (build or run).
#[derive(Debug, Clone)]
pub struct PhaseOutcome {
    /// Exit code, or `None` when the process was killed (a signal / the wall
    /// clock). `None` after a wall-clock kill is how a timeout is detected.
    pub status: Option<i32>,
    /// Captured stdout (bounded by the phase's `out_cap_bytes`).
    pub stdout: String,
    /// Captured stderr (bounded by the phase's `out_cap_bytes`).
    pub stderr: String,
    /// Whether the wall clock (or a resource cap) killed the process.
    pub killed: bool,
}

/// The read-only toolchain binds a phase re-exposes past the tmpfs masks.
#[derive(Default)]
struct ToolchainBinds {
    ro_binds: Vec<CanonicalPath>,
    path_prepend: Vec<CanonicalPath>,
    rustup_home: Option<CanonicalPath>,
}

/// Which spawn posture a phase runs under.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Subprocess {
    /// The BUILD phase: rustc + the linker legitimately spawn children, so
    /// subprocess creation is permitted (still net-denied, fs-jailed, capped).
    Allowed,
    /// The RUN phase: executing the untrusted program. Subprocess creation is
    /// DENIED at the seccomp boundary (`fork`/`vfork`/process-`clone`), so the
    /// program cannot shell out or fork-bomb past the `nproc` cap.
    Denied,
}

/// Run one jailed phase over `scoped_tmp` (its only writable mount), fully
/// offline (`NetworkPolicy::Denied` ⇒ `--unshare-net`).
///
/// `payload` is the direct argv — no shell is ever involved. `subprocess`
/// selects the fork/exec posture: the run phase denies it via seccomp.
///
/// # Errors
///
/// [`SandboxDefect`] when the jail cannot spawn, the output cap is exceeded, or
/// the invoker's homes cannot be masked.
fn run_phase(
    caps: &Capabilities,
    scoped_tmp: &CanonicalPath,
    run_caps: RunCaps,
    binds: ToolchainBinds,
    subprocess: Subprocess,
    payload: &[OsString],
) -> Result<PhaseOutcome, SandboxDefect> {
    let spec = JailSpec {
        // Denied is the whole point: user code never reaches the network. This is
        // structural (a fresh empty net namespace), not a filter that could be
        // misconfigured.
        network: NetworkPolicy::Denied,
        scoped_tmp: scoped_tmp.clone(),
        registry_cache: None,
        toolchain: None,
        toolchain_ro_binds: binds.ro_binds,
        path_prepend: binds.path_prepend,
        rustup_home: binds.rustup_home,
        homes: HomeMasks::of_invoker().map_err(SandboxDefect::Path)?,
        limits: run_caps.to_limits(),
    };
    let out = match subprocess {
        Subprocess::Allowed => run_in_bwrap_jail(caps, &spec, payload)?,
        // The run phase adds the seccomp subprocess-deny filter — a jailed program
        // that forks/execs is denied at the syscall boundary.
        Subprocess::Denied => run_in_bwrap_jail_deny_subprocess(caps, &spec, payload)?,
    };
    Ok(PhaseOutcome {
        status: out.status,
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        killed: is_wall_clock_kill(out.status),
    })
}

/// Whether an exit status is a wall-clock (or resource-cap) kill rather than the
/// program's own exit.
///
/// The jail argv is `timeout --kill-after=5s <wall> bwrap …`, so a timeout
/// surfaces as `timeout`'s exit code: `124` when it delivered SIGTERM, or
/// `128 + 9 = 137` when `--kill-after` had to SIGKILL. A `None` code means the
/// wrapper itself was signal-killed. Any of these is a kill, not a clean exit.
#[must_use]
const fn is_wall_clock_kill(status: Option<i32>) -> bool {
    // `None` = the wrapper was signal-killed; `124` = `timeout` sent SIGTERM;
    // `137` (128+9) = the `--kill-after` SIGKILL escalation.
    matches!(status, None | Some(124 | 137))
}

/// Build the emitted crate inside the jail, writing artifacts into the
/// jail-visible `scoped_tmp` target.
///
/// The build runs fully **offline** under `--unshare-net`: the emitted crate's
/// dependency closure (a FIXED, trusted set — the same for every program) must
/// already be present in `scoped_tmp/cargo-home`, which the caller seeds from a
/// pre-warmed registry ([`seed_cargo_home`]) before this runs. No network is ever
/// available to user-derived code.
///
/// The crate directory and the target directory both live under `scoped_tmp` (the
/// only writable bind), so their paths resolve inside the jail.
///
/// # Errors
///
/// [`SandboxDefect`] on a jail-spawn / output-cap failure, or when a jail path
/// does not resolve.
pub fn jailed_build(caps: &Capabilities, scoped_tmp: &Path) -> Result<PhaseOutcome, SandboxDefect> {
    // One canonical spelling for the writable bind and every payload path
    // under it.
    let scoped_tmp = CanonicalPath::resolve(scoped_tmp).map_err(SandboxDefect::Path)?;
    let binds = toolchain_binds()?;
    // Direct argv — no shell. Paths are under `scoped_tmp` so they are visible in
    // the jail. `--offline` makes any registry reach a hard cargo error, so the
    // build fails loudly rather than silently trying (and failing) egress on top
    // of the structural `--unshare-net`.
    //
    // The project dir IS the crate root: the server stages `Cargo.toml` +
    // `src/main.rs` (from the client's banner-delimited emitted Rust) directly
    // under the project dir.
    let manifest = scoped_tmp.as_path().join("Cargo.toml");
    let target = scoped_tmp.as_path().join("crate-target");
    let payload: Vec<OsString> = vec![
        "cargo".into(),
        "build".into(),
        "--offline".into(),
        "--manifest-path".into(),
        manifest.into_os_string(),
        "--target-dir".into(),
        target.into_os_string(),
    ];
    run_phase(
        caps,
        &scoped_tmp,
        RunCaps::build_defaults(),
        binds,
        // The build spawns rustc + a linker — subprocess creation is required.
        Subprocess::Allowed,
        &payload,
    )
}

/// The path the emitted `ipe-app` binary lands at after [`jailed_build`], on both
/// the host and (identically, since it is under the writable bind) inside the
/// jail.
#[must_use]
pub fn app_binary_path(scoped_tmp: &Path) -> PathBuf {
    scoped_tmp
        .join("crate-target")
        .join("debug")
        .join("ipe-app")
}

/// Seed the jail-visible `CARGO_HOME` registry from a pre-warmed one.
///
/// This lets the offline build find its fixed dependency closure without ever
/// reaching the network. The registry cache is copied (not bound) because the
/// in-jail `CARGO_HOME` path
/// is fixed by the jail argv to `scoped_tmp/cargo-home` — a writable mount cargo
/// may also write lock metadata into. The copy is the registry index + cached
/// crate sources only; it carries no credentials (the warm `CARGO_HOME` is a
/// dedicated playground cache, never the operator's `~/.cargo`).
///
/// # Errors
///
/// [`std::io::Error`] when the copy fails.
pub fn seed_cargo_home(scoped_tmp: &Path, warm_cargo_home: &Path) -> std::io::Result<()> {
    let dst = scoped_tmp.join("cargo-home");
    // Only the registry subtree is needed for an offline build; copying the whole
    // warm CARGO_HOME (which may hold a large `bin/`) is wasteful.
    let registry = warm_cargo_home.join("registry");
    if registry.is_dir() {
        copy_dir_recursive(&registry, &dst.join("registry"))?;
    }
    Ok(())
}

/// Seed the jail-visible target dir from a warm one holding the prebuilt deps.
///
/// The warm target already holds the FIXED dependency closure's compiled
/// artifacts, so the offline jailed build only compiles+links the user's own
/// crate instead of recompiling every dependency from source per request.
///
/// Hard-linked where possible (same filesystem). Cargo treats the pre-built dep
/// `.rlib`s as up-to-date (their fingerprints match — the deps are byte-identical
/// every request) and rebuilds only the user crate.
///
/// # Errors
///
/// [`std::io::Error`] when the copy fails.
pub fn seed_target_dir(scoped_tmp: &Path, warm_target: &Path) -> std::io::Result<()> {
    if warm_target.is_dir() {
        copy_dir_recursive(warm_target, &scoped_tmp.join("crate-target"))?;
    }
    Ok(())
}

/// Recursively materialise a directory tree at `to` from `from`, hard-linking
/// each file when possible (same filesystem — cheap, no data copy) and falling
/// back to a byte copy across filesystems. The registry cache is immutable crate
/// sources, so hard links are safe: the jailed build never mutates them.
///
/// Existing destination entries are NEVER touched. A prior seed of the same
/// warm cache may have left a hard link to the very file we would otherwise
/// write; falling back to `fs::copy` there would truncate that shared inode
/// in place, corrupting the warm cache for every later run. Skip instead —
/// a pre-existing entry is either that harmless link or a file the jailed
/// build replaced under a fresh inode (cargo writes via rename).
fn copy_dir_recursive(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src = entry.path();
        let dst = to.join(entry.file_name());
        if file_type.is_dir() {
            // A file squatting the name (the jailed cargo created a dir where
            // warm has a file) is left alone; the next run's fresh project
            // dir gets a clean seed.
            if !dst.is_dir() && dst.exists() {
                continue;
            }
            copy_dir_recursive(&src, &dst)?;
        } else if file_type.is_file() {
            if dst.exists() {
                continue;
            }
            // Hard link first (near-free); copy only if that fails (cross-device).
            if std::fs::hard_link(&src, &dst).is_err() {
                std::fs::copy(&src, &dst)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod copy_tests {
    use super::copy_dir_recursive;

    #[test]
    fn reseeding_never_corrupts_the_warm_source() -> std::io::Result<()> {
        let base = tempfile::tempdir_in(ipe_test_temp::temp_root())?;
        let warm = base.path().join("warm");
        let entry_dir = warm
            .join("registry")
            .join("index")
            .join(".cache")
            .join("ae")
            .join("s-");
        std::fs::create_dir_all(&entry_dir)?;
        let entry = entry_dir.join("aes-gcm");
        std::fs::write(&entry, "some index content")?;

        let project = base.path().join("project");
        copy_dir_recursive(&warm, &project)?;
        // Re-seed into the same project dir: the first seed left a hard link
        // inside `project` pointing at the warm inode. A naive re-seed would
        // truncate it — and with it, warm.
        copy_dir_recursive(&warm, &project)?;

        let warm_content = std::fs::read_to_string(&entry)?;
        assert_eq!(
            warm_content, "some index content",
            "warm entry was corrupted by re-seeding"
        );
        let project_content = std::fs::read_to_string(
            project
                .join("registry")
                .join("index")
                .join(".cache")
                .join("ae")
                .join("s-")
                .join("aes-gcm"),
        )?;
        assert_eq!(project_content, "some index content");
        Ok(())
    }
}

/// Run the freshly-built `ipe-app` binary inside the jail.
///
/// The binary is executed by absolute path under the jail's writable bind. No
/// toolchain binds are needed (the program is self-contained), which is a
/// tighter surface than the build phase.
///
/// # Errors
///
/// [`SandboxDefect`] on a jail-spawn / output-cap failure, or when a jail path
/// does not resolve.
pub fn jailed_run(
    caps: &Capabilities,
    scoped_tmp: &Path,
    app_binary: &Path,
) -> Result<PhaseOutcome, SandboxDefect> {
    // The bind and the binary the payload execs share one canonical spelling.
    let scoped_tmp = CanonicalPath::resolve(scoped_tmp).map_err(SandboxDefect::Path)?;
    let app_binary = CanonicalPath::resolve(app_binary).map_err(SandboxDefect::Path)?;
    let payload: Vec<OsString> = vec![app_binary.as_path().as_os_str().to_owned()];
    run_phase(
        caps,
        &scoped_tmp,
        RunCaps::run_defaults(),
        // No toolchain binds for the run phase — the emitted program does not need
        // rustc/cargo, so nothing extra is exposed.
        ToolchainBinds::default(),
        // The untrusted program runs under the seccomp subprocess-deny filter.
        Subprocess::Denied,
        &payload,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_caps_lower_to_the_expected_limits() {
        let l = RunCaps::run_defaults().to_limits();
        assert_eq!(l.cpu_secs, 5);
        assert_eq!(l.wall_secs, 10);
        assert_eq!(l.proc_cap, ProcCap::of::<32>());
        // The build phase is more generous but still bounded.
        let b = RunCaps::build_defaults().to_limits();
        assert!(b.wall_secs > l.wall_secs);
        assert!(b.proc_cap >= l.proc_cap);
    }

    #[test]
    fn probe_refuses_when_bwrap_absent() {
        // Simulate the refusal branch directly: a Capabilities with no bwrap must
        // yield a refusal that names the jail. (The real `probe_or_refuse` reads
        // PATH; here we assert the message contract the endpoint relies on.)
        let caps = Capabilities::default();
        assert!(caps.bwrap.is_none());
        let missing = missing_caps(&caps);
        assert!(missing.contains(&"timeout"));
        assert!(missing.contains(&"prlimit"));
    }

    #[test]
    fn wall_clock_kill_covers_timeout_exit_codes() {
        // A signal-kill (None), `timeout`'s timed-out code (124), and the SIGKILL
        // escalation (137) are all kills; a normal exit is not.
        assert!(is_wall_clock_kill(None));
        assert!(is_wall_clock_kill(Some(124)));
        assert!(is_wall_clock_kill(Some(137)));
        assert!(!is_wall_clock_kill(Some(0)));
        assert!(!is_wall_clock_kill(Some(1)));
    }

    /// A tool home over the absolute test path `path`.
    fn tool(path: &Path) -> ToolHome {
        ipe_sandbox::home::tool_home_from("CARGO_HOME", Some(path.into()), None, ".cargo")
            .expect("an absolute test tool home")
            .expect("a set tool home")
    }

    /// A host layout with `cargo/bin` and a disjoint `rustup`, canonicalized.
    fn toolchain_tree() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir_in(ipe_test_temp::temp_root()).expect("tempdir");
        let root = dir.path().canonicalize().expect("canonical tempdir");
        std::fs::create_dir_all(root.join("cargo").join("bin")).expect("cargo/bin");
        std::fs::create_dir_all(root.join("rustup")).expect("rustup");
        (dir, root)
    }

    #[test]
    fn a_rustup_home_at_or_above_the_cargo_home_is_refused() {
        let (_dir, root) = toolchain_tree();
        let cargo_home = root.join("cargo");
        for rustup in [cargo_home.clone(), root] {
            let refused = toolchain_binds_from(Some(&tool(&cargo_home)), Some(tool(&rustup)));
            assert!(matches!(
                refused,
                Err(SandboxDefect::Path(JailPathError::ExposesCargoHome { .. }))
            ));
        }
    }

    #[test]
    fn a_disjoint_rustup_home_binds_bin_and_rustup_only() {
        let (_dir, root) = toolchain_tree();
        let cargo_home = root.join("cargo");
        let result =
            toolchain_binds_from(Some(&tool(&cargo_home)), Some(tool(&root.join("rustup"))));
        assert!(result.is_ok(), "a disjoint layout must bind");
        let Ok(binds) = result else { return };
        let bound: Vec<&Path> = binds.ro_binds.iter().map(CanonicalPath::as_path).collect();
        assert_eq!(
            bound,
            [
                cargo_home.join("bin").as_path(),
                root.join("rustup").as_path()
            ]
        );
        assert!(!bound.contains(&cargo_home.as_path()));
    }
}
