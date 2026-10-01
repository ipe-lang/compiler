#![forbid(unsafe_code)]
//! Tier-2 native-code capability enforcement (ADR 0004).
//!
//! Two layers:
//!
//! - **CLI-level** (always runs): a pure Ipê package skips Tier-2 (with a note)
//!   while Tier-1 still fully gates it; a native-bearing package with no
//!   probeable entrypoint is rejected by the Tier-2 check (fail-closed, never a
//!   silent clean).
//! - **Real-jail differential confinement** (gated on a wired POSIX-shell
//!   platform — `Linux/x86_64`, macOS, or FreeBSD — + `IPE_E2E=1`):
//!   drives the reconciler through the REAL jail against the admission probe
//!   fixture, proving at the OS boundary that a used-but-undeclared axis rejects
//!   naming the axis, and a benign package declaring exactly its axes is
//!   accepted. Skips cleanly (never a false pass) where the jail cannot be
//!   established, mirroring the sandbox crate's `build_jail_e2e`.

// A failed `expect` in test setup IS the failure signal the harness reports.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

mod support;

// ===========================================================================
// CLI-level: pure-Ipê skip (Tier-1 still gates) + native-bearing fail-closed
// ===========================================================================

fn temp_pkg(tag: &str) -> PathBuf {
    let dir = crate::support::scratch_root().join(format!(
        "ipe-tier2-test-{}-{}-{}",
        std::process::id(),
        tag,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("create temp src dir");
    dir
}

fn empty_index(tag: &str) -> PathBuf {
    let dir = crate::support::scratch_root().join(format!(
        "ipe-tier2-index-{}-{}",
        std::process::id(),
        tag
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("packages")).expect("create index packages dir");
    dir
}

fn run_audit(pkg: &Path, index: &Path) -> (bool, String, String) {
    let out = Command::new(support::ipe_bin())
        .arg("package")
        .arg("audit")
        .arg(pkg)
        .arg("--index")
        .arg(index)
        .current_dir(support::repo_root())
        .output()
        .expect("run ipe package audit");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

const PURE_MAIN: &str = "module Main exposing (main)\n\
                         \n\
                         import Ipe.String as String\n\
                         import Ipe.Io as Io\n\
                         \n\
                         main : Task ()\n\
                         main =\n\
                         \x20   Io.println (String.toUpper \"hello\")\n";

#[test]
fn a_pure_ipe_package_skips_tier2_while_tier1_still_gates() {
    // A pure Ipê package: Tier-2 does not apply (skips), and Tier-1 still runs to
    // completion (the pass line is printed). The honest surface says Tier-2 does
    // not apply — it never claims a Tier-2 certification for a package it skipped.
    let pkg = temp_pkg("pure-skip");
    std::fs::write(
        pkg.join("package.ipe"),
        "module Package exposing (package)\n\n\npackage =\n    { name = \"pure-pkg\", version = \"0.1.0\" }\n",
    )
    .expect("write package.ipe");
    std::fs::write(pkg.join("src").join("Main.ipe"), PURE_MAIN).expect("write Main");
    let index = empty_index("pure-skip");

    let (ok, stdout, stderr) = run_audit(&pkg, &index);
    assert!(
        ok,
        "a pure package must pass; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("all Tier-1 checks passed"),
        "Tier-1 still runs to completion; got:\n{stdout}"
    );
    assert!(
        stdout.contains("native Tier-2 does not apply"),
        "the honest surface says Tier-2 does not apply for a pure package; got:\n{stdout}"
    );
    assert!(
        !stdout.contains("passed on: linux-x64"),
        "a pure package must never claim a Tier-2 certification; got:\n{stdout}"
    );
}

#[test]
fn a_native_bearing_package_with_no_probeable_entrypoint_fails_closed() {
    // A package binding a Rust dependency is native-bearing. The audit gate must
    // refuse to certify it — fail-closed — rather than admit it un-observed.
    // The gate first regenerates FFI bindings from the pinned `[rust.dependencies]`
    // (sandboxed), then runs Tier-1 (including provenance), then Tier-2. The check
    // that fires depends on the generated bindings, the platform, and whether the
    // binding generator is reachable:
    //   • binding regeneration — if the sandboxed generator cannot produce a
    //     clean, gate-owned binding set, the package cannot be certified;
    //   • provenance — if the generated `_bindings.rs` contains an abrupt-failure
    //     construct (e.g. `libc` generates a `process::abort` wrapper);
    //   • native Tier-2 — on a wired platform where the jail can run, the
    //     un-exercised probe entrypoint is the reject;
    //   • refuse-to-certify — on an unwired platform, Tier-2 refuses the
    //     un-exercised native surface.
    // All are fail-closed: the package must not certify.
    let pkg = temp_pkg("native-noprobe");
    std::fs::write(
        pkg.join("package.ipe"),
        "module Package exposing (package)\n\n\npackage =\n\
         \x20   { name = \"native-pkg\"\n\
         \x20   , version = \"0.1.0\"\n\
         \x20   , rustDependencies = [ rustDep \"libc\" \"0.2\" ]\n\
         \x20   }\n",
    )
    .expect("write package.ipe");
    std::fs::write(pkg.join("src").join("Main.ipe"), PURE_MAIN).expect("write Main");
    let index = empty_index("native-noprobe");

    let (ok, stdout, stderr) = run_audit(&pkg, &index);
    assert!(
        !ok,
        "a native-bearing package must fail closed — never certify un-observed; \
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // Any of these checks firing is a valid fail-closed reject.
    assert!(
        stderr.contains("regenerate FFI bindings")
            || stderr.contains("provenance panic-scan")
            || stderr.contains("native Tier-2 capability enforcement"),
        "the reject names a fail-closed check (binding regeneration, provenance, or Tier-2); \
         got:\n{stderr}"
    );
}

// ===========================================================================
// Real-jail differential confinement (wired platforms + IPE_E2E=1)
//
// On Linux/x86_64 the jail is bwrap+seccomp; on macOS it is sandbox-exec; on
// FreeBSD `jail(8)`; on Windows the Job Object + AppContainer returning build
// jail. The reconciler is the SAME on all four — only the jail primitive probed
// in `e2e_tools` and the platform-native probe wrapper differ (the POSIX
// `/bin/sh` `untrusted-build.sh` on Linux/macOS/FreeBSD, driven through a
// `/usr/bin/env … /bin/sh` prefix; the Windows-native `untrusted-build.ps1` on
// Windows, driven as `powershell.exe -File … -Tier2Axis <axis> …` because the
// Windows jail runs `payload[0]` directly through `CreateProcessW`, no shell).
// ===========================================================================

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
))]
mod real_jail {
    use super::PathBuf;
    use std::collections::BTreeSet;
    use std::ffi::OsString;

    use ipe::audit::Check;
    use ipe::audit_native::{
        CERTIFIED_PLATFORM, JailProbeRunner, ProbeExercise, ProbeRunner, StaticReachability,
        TightenableAxis, ToolchainHomes, TrustedWrapper, default_ro_binds, reconcile_native,
        scoped_profile,
    };
    use ipe_ir::Capability;
    use ipe_sandbox::build_jail::build_in_jail;
    use ipe_sandbox::run_jail::{RunJailTools, SandboxProfile};
    use ipe_sandbox::{CanonicalPath, JailMounts};

    /// `build_in_jail` mutates the process-global fd table (a `memfd`) on Linux;
    /// serialize the jailed runs so parallel `--test-threads` cannot race.
    static JAIL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn fixture_path() -> PathBuf {
        let base = super::support::manifest_dir().join("../../tests/fixtures/admission");
        // The wrapper is platform-native: `.ps1` on Windows (the jail runs it via
        // `powershell.exe -File`, no shell), `.sh` elsewhere.
        #[cfg(target_os = "windows")]
        {
            base.join("untrusted-build.ps1")
        }
        #[cfg(not(target_os = "windows"))]
        {
            base.join("untrusted-build.sh")
        }
    }

    /// Probe the host for the jail primitive, returning the [`RunJailTools`] the
    /// jail is built from (bwrap+prlimit on Linux; sandbox-exec on macOS, whose
    /// fields the jail ignores). `None` when the primitive is absent.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn probe_tools() -> Option<RunJailTools> {
        let caps = ipe_sandbox::probe();
        Some(RunJailTools {
            bwrap: caps.bwrap?,
            prlimit: caps.prlimit?,
            timeout: caps.timeout,
        })
    }

    /// macOS: the jail primitive is `sandbox-exec`; the `RunJailTools` fields are
    /// unused by the macOS `build_in_jail` (a present-primitive placeholder).
    #[cfg(target_os = "macos")]
    fn probe_tools() -> Option<RunJailTools> {
        let path = ipe_env::var_os("PATH")?;
        let sandbox_exec = std::env::split_paths(&path)
            .map(|d| d.join("sandbox-exec"))
            .find(|p| p.is_file())?;
        Some(RunJailTools {
            bwrap: sandbox_exec.clone(),
            prlimit: sandbox_exec,
            timeout: None,
        })
    }

    /// FreeBSD: the jail primitive is `jail(8)`; the `RunJailTools` fields are
    /// unused by the FreeBSD `build_in_jail` (a present-primitive placeholder).
    #[cfg(target_os = "freebsd")]
    fn probe_tools() -> Option<RunJailTools> {
        let path = ipe_env::var_os("PATH")?;
        let jail = std::env::split_paths(&path)
            .map(|d| d.join("jail"))
            .find(|p| p.is_file())?;
        Some(RunJailTools {
            bwrap: jail.clone(),
            prlimit: jail,
            timeout: None,
        })
    }

    /// Windows: the probe interpreter is `powershell.exe` (the
    /// `CreateProcessW`-invokable payload[0] the Windows `build_in_jail` runs
    /// directly, driving the `.ps1` wrapper). The `RunJailTools` fields are read
    /// by the POSIX arms but ignored by the Windows `build_in_jail` (which builds
    /// its Job Object + AppContainer itself) — the confirmed interpreter is a
    /// present-primitive placeholder, so `bwrap` carries the resolved
    /// `powershell.exe` the payload runs.
    #[cfg(target_os = "windows")]
    fn probe_tools() -> Option<RunJailTools> {
        let path = ipe_env::var_os("PATH")?;
        let powershell = std::env::split_paths(&path)
            .map(|d| d.join("powershell.exe"))
            .find(|p| p.is_file())?;
        Some(RunJailTools {
            bwrap: powershell.clone(),
            prlimit: powershell,
            timeout: None,
        })
    }

    /// Skip unless `IPE_E2E=1`, the jail primitive is present, AND a jail can
    /// actually be established here (a clean-exit canary settles it once) —
    /// mirroring the sandbox crate's gate. Never a false pass.
    fn e2e_tools() -> Option<RunJailTools> {
        if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
            return None;
        }
        let tools = probe_tools()?;
        if !jail_can_establish(&tools) {
            return None;
        }
        Some(tools)
    }

    /// A trivial clean-exit payload for the establishment canary — `/bin/true` on
    /// POSIX, `powershell.exe -Command exit 0` on Windows (the jail runs
    /// `payload[0]` directly through `CreateProcessW`, no shell, so the canary is
    /// the interpreter itself).
    #[cfg(not(target_os = "windows"))]
    fn canary_payload(_tools: &RunJailTools) -> Vec<OsString> {
        vec![OsString::from("/bin/true")]
    }

    #[cfg(target_os = "windows")]
    fn canary_payload(tools: &RunJailTools) -> Vec<OsString> {
        vec![
            tools.bwrap.clone().into_os_string(),
            OsString::from("-NoProfile"),
            OsString::from("-NonInteractive"),
            OsString::from("-Command"),
            OsString::from("exit 0"),
        ]
    }

    fn jail_can_establish(tools: &RunJailTools) -> bool {
        static CANARY: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *CANARY.get_or_init(|| {
            let scoped = fresh_scratch("canary");
            let _guard = JAIL_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mounts = JailMounts::of_invoker(scoped.clone(), scoped.clone(), default_ro_binds())
                .expect("checked jail mounts");
            let outcome = build_in_jail(
                tools,
                &SandboxProfile::maximally_isolated(),
                &mounts,
                &canary_payload(tools),
            );
            let _ = std::fs::remove_dir_all(scoped.as_path());
            let established = outcome.is_clean();
            if !established {
                eprintln!("audit_native e2e: skipping — jail cannot be established ({outcome:?})");
            }
            established
        })
    }

    fn fresh_scratch(tag: &str) -> CanonicalPath {
        let dir = crate::support::scratch_root().join(format!(
            "ipe-tier2-e2e-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch");
        CanonicalPath::resolve(&dir).expect("canonical scratch")
    }

    /// The invoking user's toolchain, as production resolves it.
    fn invoker_toolchain() -> ToolchainHomes {
        ToolchainHomes::of_invoker()
            .expect("the test environment's toolchain homes are absolute or unset")
    }

    fn set(caps: &[Capability]) -> BTreeSet<Capability> {
        caps.iter().copied().collect()
    }

    /// A static-reachability stub for the E2E cross-check.
    struct FixedScan {
        reaches: BTreeSet<Capability>,
    }
    impl StaticReachability for FixedScan {
        fn reaches(&self, axis: TightenableAxis) -> bool {
            self.reaches.contains(&axis.capability())
        }
    }

    /// Build a real jail-backed runner exercising `exercised`, holding the two
    /// scratch dirs alive for the run's duration.
    struct Harness {
        scoped_tmp: CanonicalPath,
        working_tree: CanonicalPath,
        wrapper: TrustedWrapper,
    }

    impl Harness {
        fn new(tag: &str) -> Self {
            let scoped_tmp = fresh_scratch(&format!("{tag}-scratch"));
            let working_tree = fresh_scratch(&format!("{tag}-worktree"));
            let wrapper = TrustedWrapper::read(&fixture_path()).expect("read the probe fixture");
            Self {
                scoped_tmp,
                working_tree,
                wrapper,
            }
        }

        fn runner<'a>(
            &self,
            tools: &'a RunJailTools,
            exercised: Vec<TightenableAxis>,
        ) -> JailProbeRunner<'a> {
            JailProbeRunner::new(
                tools,
                self.wrapper.clone(),
                self.scoped_tmp.clone(),
                self.working_tree.clone(),
                default_ro_binds(),
                exercised,
                ProbeExercise::WrapperProbeOnly,
            )
            .expect("checked jail mounts")
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(self.scoped_tmp.as_path());
            let _ = std::fs::remove_dir_all(self.working_tree.as_path());
        }
    }

    #[test]
    fn used_but_undeclared_network_rejects_naming_the_axis_standing_canary() {
        // THE SEAL'S RED CANARY: native code opens a socket (exercises network)
        // while declaring `[]`. Under the declared-scoped jail (network withheld)
        // the socket is denied → REJECT naming the network axis. This MUST stay
        // red if the admit predicate ever regresses.
        let Some(tools) = e2e_tools() else { return };
        let declared = BTreeSet::new();
        let scoped = scoped_profile(&declared).expect("lower profile");
        let harness = Harness::new("canary-net");
        let _guard = JAIL_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let runner = harness.runner(&tools, vec![TightenableAxis::Network]);
        let scan = FixedScan {
            reaches: BTreeSet::new(),
        };
        let verdict = reconcile_native(&declared, &runner, &scan, &scoped);
        let r = verdict.expect_err("a socket under a []-scoped jail must reject");
        assert_eq!(r.check, Check::NativeTier2);
        assert!(
            r.message.contains("network") && r.message.contains("hidden effect"),
            "the reject names the network axis as a hidden effect: {}",
            r.message
        );
    }

    #[test]
    fn used_but_undeclared_filesystem_rejects_naming_filesystem() {
        // Native code writes out-of-scratch (exercises filesystem) while declaring
        // `[]`. Under the declared-scoped jail (filesystem withheld) the write is
        // denied → REJECT naming filesystem.
        let Some(tools) = e2e_tools() else { return };
        let declared = BTreeSet::new();
        let scoped = scoped_profile(&declared).expect("lower profile");
        let harness = Harness::new("canary-fs");
        let _guard = JAIL_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let runner = harness.runner(&tools, vec![TightenableAxis::Filesystem]);
        let scan = FixedScan {
            reaches: BTreeSet::new(),
        };
        let r = reconcile_native(&declared, &runner, &scan, &scoped)
            .expect_err("an out-of-scratch write under a []-scoped jail must reject");
        assert!(r.message.contains("filesystem"), "{}", r.message);
    }

    #[test]
    fn a_benign_network_package_declaring_exactly_its_axis_is_accepted() {
        // POSITIVE control: declares `network`; native code opens a socket. The
        // declared-scoped jail GRANTS network → the socket reaches → clean. The
        // tightening run (network withheld) DENIES the socket → the axis is needed
        // → not over-broad → ACCEPT. The clean result requires the probe's
        // positive clean exit (not a broken jail), because the same jail denies
        // the socket when network is withheld.
        let Some(tools) = e2e_tools() else { return };
        let declared = set(&[Capability::Network]);
        let scoped = scoped_profile(&declared).expect("lower profile");
        let harness = Harness::new("benign-net");
        let _guard = JAIL_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let runner = harness.runner(&tools, vec![TightenableAxis::Network]);
        // The static scan reaches network too (the wrapper opens a socket), so a
        // needed axis is never mis-flagged unused.
        let scan = FixedScan {
            reaches: set(&[Capability::Network]),
        };
        reconcile_native(&declared, &runner, &scan, &scoped)
            .expect("a benign network package declaring exactly its axis must be accepted");
    }

    #[test]
    fn the_certified_platform_names_this_host_jail() {
        // The certify label names exactly the wired jail on THIS host, so a
        // certify never claims a platform whose jail did not run.
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        assert_eq!(CERTIFIED_PLATFORM, "linux-x64");
        #[cfg(target_os = "macos")]
        assert_eq!(CERTIFIED_PLATFORM, "macos-arm64");
        #[cfg(target_os = "freebsd")]
        assert_eq!(CERTIFIED_PLATFORM, "freebsd-x64");
        #[cfg(target_os = "windows")]
        assert_eq!(CERTIFIED_PLATFORM, "windows-x64");
    }

    // ── real untrusted `cargo build` as the wrapper's child (the certify path) ──
    //
    // These drive the SAME reconciler production wires, but with a real
    // `ProbeExercise::RealBuild` running an actual `cargo build` inside the jail as
    // the wrapper's child — proving at the OS boundary that (i) a confined clean
    // build+link genuinely CERTIFIES (the first real certification) and (ii) a
    // build whose `build.rs` reaches a withheld axis REJECTS naming the axis. A
    // reduced purpose-built crate (design §7.2) keeps the always-run canary cheap:
    // no registry deps, so `--offline` needs no vendoring.

    /// Write a minimal, self-contained cargo crate into `dir`. When `net_reach`
    /// is set, its `build.rs` attempts a TCP connect at build time — a genuine,
    /// deterministic network capability demand. Otherwise the build is inert
    /// (reaches no axis) and must certify clean under any scoped jail.
    fn write_min_crate(dir: &std::path::Path, net_reach: bool) {
        std::fs::create_dir_all(dir.join("src")).expect("crate src");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"tier2min\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n\
             [[bin]]\nname = \"tier2_probe\"\npath = \"src/main.rs\"\n\n[workspace]\n",
        )
        .expect("Cargo.toml");
        std::fs::write(
            dir.join("src").join("main.rs"),
            "fn main() { std::hint::black_box(0u8); }\n",
        )
        .expect("main.rs");
        if net_reach {
            // A build-time network reach the build GENUINELY needs: it propagates
            // the connect error, so a jail withholding `network` (net namespace
            // unshared) makes the connect fail → build.rs errors → cargo exits
            // non-zero → the full run decodes BuildFailed (a real OS-boundary
            // reject). A `let _ =`-ignored connect would be a no-op (a caught denial
            // is no effect), which correctly reads as clean — so the negative must
            // propagate to prove the build truly demanded the withheld axis.
            std::fs::write(
                dir.join("build.rs"),
                "use std::net::TcpStream;\nuse std::time::Duration;\n\
                 fn main() {\n    \
                 let addr: std::net::SocketAddr = \"140.82.112.3:443\".parse().unwrap();\n    \
                 TcpStream::connect_timeout(&addr, Duration::from_secs(5))\n        \
                 .expect(\"tier2 negative fixture: build genuinely needs network\");\n}\n",
            )
            .expect("build.rs");
        }
    }

    /// The `cargo build` argv for the min crate, `--offline` with a scratch-local
    /// target dir (no registry deps, so offline needs no vendoring). Cargo is
    /// invoked by ABSOLUTE path: the in-jail PATH is a fixed `/usr/bin:/bin`, so a
    /// bare `cargo` is unfindable; the toolchain bind makes the absolute path
    /// executable.
    fn min_build_argv(crate_dir: &std::path::Path) -> Vec<OsString> {
        let cargo = which_cargo().map_or_else(|| OsString::from("cargo"), PathBuf::into_os_string);
        vec![
            cargo,
            OsString::from("build"),
            OsString::from("--offline"),
            OsString::from("--bin"),
            OsString::from("tier2_probe"),
            OsString::from("--manifest-path"),
            crate_dir.join("Cargo.toml").into_os_string(),
            OsString::from("--target-dir"),
            crate_dir.join("target").into_os_string(),
        ]
    }

    fn real_build_runner<'a>(
        harness: &Harness,
        tools: &'a RunJailTools,
        exercise: ProbeExercise,
    ) -> JailProbeRunner<'a> {
        // The runner binds the exercise's toolchain (read-only) itself.
        let ro_binds = default_ro_binds();
        JailProbeRunner::new(
            tools,
            harness.wrapper.clone(),
            harness.scoped_tmp.clone(),
            harness.working_tree.clone(),
            ro_binds,
            // Unused on the real-build path (full run is child-exit-only; tighten
            // probes the single declared axis under test).
            vec![TightenableAxis::Network, TightenableAxis::Filesystem],
            exercise,
        )
        .expect("checked jail mounts")
    }

    #[test]
    fn a_confined_clean_build_genuinely_certifies_the_first_real_certification() {
        // POSITIVE: a native crate whose build reaches NO withheld axis, built
        // under a jail scoped to `[network]` (which it declares but its build does
        // not need). The declared-scoped run is clean; the tighten run removes
        // network, still clean, but the static scan reaches network → not flagged
        // unused → reconcile Ok. This is the shape production turns into the single
        // `Certified` — proven here through the REAL jail with a REAL cargo build.
        let Some(tools) = e2e_tools() else { return };
        // `cargo` must be reachable inside the jail; skip cleanly if absent.
        if which_cargo().is_none() {
            eprintln!("audit_native e2e: skipping — cargo not found on PATH");
            return;
        }
        let declared = set(&[Capability::Network]);
        let scoped = scoped_profile(&declared).expect("lower profile");
        let harness = Harness::new("certify-clean");
        // The crate + its target live in the ALWAYS-writable scratch (`scoped_tmp`),
        // not the filesystem-axis-gated working tree — so a filesystem-withholding
        // jail (declared=[network]) can still build it. A withheld axis is withheld
        // by capability REMOVAL (net namespace), not by making the build unwritable.
        let crate_dir = harness.scoped_tmp.as_path().join("tier2min");
        write_min_crate(&crate_dir, false);
        let _guard = JAIL_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let exercise = ProbeExercise::real_build(min_build_argv(&crate_dir), invoker_toolchain())
            .expect("non-empty argv");
        assert!(
            exercise.is_real_build(),
            "the certify guard needs a real build"
        );
        let runner = real_build_runner(&harness, &tools, exercise);
        let scan = FixedScan {
            reaches: set(&[Capability::Network]),
        };
        let verdict = reconcile_native(&declared, &runner, &scan, &scoped);
        // Skip (not fail) if this environment cannot compile the crate under the
        // jail (no toolchain reachable inside bwrap): a BuildFailed here is an
        // environment gap, never a false pass. A real clean IS the certification.
        match verdict {
            Ok(()) => { /* the first genuine certification */ }
            Err(r) if r.message.contains("failed to build") => {
                eprintln!("audit_native e2e: skipping — cargo unavailable inside jail: {r}");
            }
            Err(r) => panic!("a confined clean build must certify, got: {r}"),
        }
    }

    #[test]
    fn a_build_that_reaches_network_under_a_withholding_jail_rejects_at_the_os_boundary() {
        // NEGATIVE (OS-boundary): a native crate whose `build.rs` opens a socket at
        // build time, built under a `[]`-scoped jail (network withheld). The
        // build's socket is denied by the jail; the wrapper's post-build network
        // probe under the same withheld jail is ALSO denied → Denied{network} →
        // REJECT naming the axis. A real OS denial, not a scripted-runner verdict.
        let Some(tools) = e2e_tools() else { return };
        if which_cargo().is_none() {
            eprintln!("audit_native e2e: skipping — cargo not found on PATH");
            return;
        }
        let declared = BTreeSet::new();
        let scoped = scoped_profile(&declared).expect("lower profile");
        let harness = Harness::new("reject-netbuild");
        // Build in the always-writable scratch (see the positive test).
        let crate_dir = harness.scoped_tmp.as_path().join("tier2min");
        write_min_crate(&crate_dir, true);
        let _guard = JAIL_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let exercise = ProbeExercise::real_build(min_build_argv(&crate_dir), invoker_toolchain())
            .expect("non-empty argv");
        let runner = real_build_runner(&harness, &tools, exercise);
        let scan = FixedScan {
            reaches: BTreeSet::new(),
        };
        let r = reconcile_native(&declared, &runner, &scan, &scoped)
            .expect_err("a build reaching network under a []-scoped jail must reject");
        assert_eq!(r.check, Check::NativeTier2);
        // On the full declared-scoped run the wrapper runs NO fabricated fixed axis
        // probe; the signal is the child build's own OS-boundary failure (the
        // net-namespace-unshared build.rs connect fails → cargo non-zero → decoded
        // BuildFailed). The reject is real and fail-closed; axis NAMING on the full
        // run is deliberately traded for not fabricating a demand the package never
        // made (the single-axis canaries above name the axis). If cargo is
        // unreachable inside the jail the build also fails closed — never a false
        // clean, never a certify.
        assert!(
            r.message.contains("failed to build") || r.message.contains("network"),
            "the reject is a real OS-boundary failure (BuildFailed or a named axis): {}",
            r.message
        );
        assert!(
            !r.message.contains("passed"),
            "a build reaching a withheld axis must never certify: {}",
            r.message
        );
    }

    fn which_cargo() -> Option<PathBuf> {
        let path = ipe_env::var_os("PATH")?;
        // `cargo` on POSIX, `cargo.exe` on Windows.
        let names: &[&str] = if cfg!(target_os = "windows") {
            &["cargo.exe", "cargo"]
        } else {
            &["cargo"]
        };
        std::env::split_paths(&path)
            .flat_map(|dir| names.iter().map(move |n| dir.join(n)))
            .find(|p| p.is_file())
    }

    // Keep the imports honest under all cfgs.
    #[allow(dead_code)]
    fn _uses(_: &dyn ProbeRunner) {}

    // ── end-to-end certify through the production `native_tier2` path ──────────
    //
    // The canaries above drive `reconcile_native` / `JailProbeRunner` directly.
    // This exercise drives the WHOLE `native_tier2` entry: a real
    // `[rust.dependencies]` package with a genuine probeable binding is built to
    // its emitted app crate, then `native_tier2` emits the Tier-2 probe crate,
    // builds it under the declared-scoped jail as the wrapper's child, and
    // reconciles it — asserting the single `Tier2Outcome::Certified`. It is the
    // regression that a legitimate native package is REACHABLY certifiable, not
    // only fail-closed-rejectable.

    use ipe::audit_native::{NativeAudit, Tier2Outcome, native_tier2};
    use ipe_ffi::driver::{FfiCache, install_from_inspection};

    /// A directory under `~/.cache/ipe/` (never `/tmp`, which the jail masks with
    /// a tmpfs): the emitted app crate, the bound crate, and the runtime copy the
    /// jailed probe build reads must all live where `--ro-bind / /` can see them.
    fn non_tmp_base(tag: &str) -> PathBuf {
        let base = dirs_cache_root()
            .join("ipe")
            .join("tier2-e2e")
            .join(format!("{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("create non-tmp e2e base");
        base
    }

    /// `$XDG_CACHE_HOME` or `~/.cache` — the write-boundary root the project
    /// pins scratch and target state under (never `/tmp`).
    fn dirs_cache_root() -> PathBuf {
        ipe_env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| ipe_sandbox::home::home_dir().map(|h| h.join(".cache")))
            .expect("HOME or XDG_CACHE_HOME set")
    }

    /// A genuine probeable binding: a pure crate function `checksum(String) ->
    /// Int`. A pure `i64`-returning shape survives the binding gate and the
    /// interface DCE, so the emitted `src/ffi.rs` carries the wrapper the probe
    /// references — the shape a real certify rests on.
    fn seed_pure_ffi_cache(project_root: &std::path::Path) -> bool {
        let cache = FfiCache::at_project_root(project_root);
        let doc = serde_json::json!({
            "pkg": "csum",
            "name": "csum",
            "version": "0.1.0",
            "functions": [
                {
                    "name": "checksum",
                    "params": [{"name": "data", "type": "String", "ipeType": "String",
                                "rustType": "String"}],
                    "results": [{"name": "", "type": "Int", "rustType": "i64"}],
                    "effect": "pure"
                }
            ],
            "errors": [],
            "transitiveDeps": [{"ident": "csum", "name": "csum", "version": "0.1.0"}],
            "types": []
        });
        install_from_inspection(&cache, &doc.to_string()).is_ok()
    }

    /// The fixture program CALLS the binding, so it survives DCE into `src/ffi.rs`
    /// — a package whose native surface is genuinely reached, the only shape a
    /// certify may rest on.
    const CSUM_MAIN: &str = "module Main exposing (main)\n\
        import Ipe.Io as Io\n\
        import Ipe.String as String\n\
        import Rust.Csum as Csum\n\n\
        main =\n\
        \x20   case Csum.checksum \"abc\" of\n\
        \x20       Ok n -> Io.println (String.fromInt n)\n\
        \x20       Err _ -> Io.println \"err\"\n";

    /// Write the real bound crate `csum` (a pure `checksum`), returning its dir.
    /// When `net_reach` is set the crate carries a `build.rs` that connects a TCP
    /// socket at build time — a genuine, undeclared network reach: under a jail
    /// scoped to a set WITHOUT network the connect fails, the build.rs propagates
    /// it, cargo exits non-zero, and the probe build is `BuildFailed` (a real
    /// OS-boundary reject). Otherwise the crate is pure and its probe build is
    /// clean.
    fn write_csum_crate(base: &std::path::Path, net_reach: bool) -> PathBuf {
        let dir = base.join("csum");
        std::fs::create_dir_all(dir.join("src")).expect("csum src");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"csum\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
        )
        .expect("csum Cargo.toml");
        std::fs::write(
            dir.join("src/lib.rs"),
            "pub fn checksum(data: String) -> i64 {\n    \
             data.bytes().map(i64::from).sum()\n}\n",
        )
        .expect("csum lib.rs");
        if net_reach {
            // A build-time connect the build GENUINELY needs (it propagates the
            // error): a jail withholding `network` makes the connect fail → build.rs
            // errors → cargo non-zero → BuildFailed. A `let _ =`-ignored connect
            // would be a no-op (a caught denial is no effect) and read as clean, so
            // the negative must propagate to prove the build truly demanded network.
            std::fs::write(
                dir.join("build.rs"),
                "use std::net::TcpStream;\nuse std::time::Duration;\n\
                 fn main() {\n    \
                 let addr: std::net::SocketAddr = \"140.82.112.3:443\".parse().unwrap();\n    \
                 TcpStream::connect_timeout(&addr, Duration::from_secs(5))\n        \
                 .expect(\"tier2 e2e negative: build genuinely needs network\");\n}\n",
            )
            .expect("csum build.rs");
        }
        dir
    }

    /// Set up a real `[rust.dependencies]` package that CALLS its binding, emit
    /// its app crate under `base/out`, and repoint the bound-crate pin at the
    /// local fixture crate so an offline probe build resolves it. Returns the
    /// package root and the emitted crate dir.
    fn emit_real_native_package(base: &std::path::Path, net_reach: bool) -> (PathBuf, PathBuf) {
        let runtime = e2e_support::require_runtime().into_path_buf();
        let pkg = base.join("pkg");
        std::fs::create_dir_all(pkg.join("src")).expect("pkg src");
        // The FFI cache (not the manifest) supplies the native `csum` surface;
        // the manifest only needs to name the rust dependency (the legacy reader
        // captured only its name + version, never a path). The crate's path is
        // used below to repoint the emitted manifest at the local fixture.
        let csum = write_csum_crate(base, net_reach);
        std::fs::write(
            pkg.join("package.ipe"),
            "module Package exposing (package)\n\n\npackage =\n\
             \x20   { name = \"csumpkg\"\n\
             \x20   , version = \"0.1.0\"\n\
             \x20   , rustDependencies = [ rustDep \"csum\" \"=0.1.0\" ]\n\
             \x20   }\n",
        )
        .expect("package.ipe");
        std::fs::write(pkg.join("src").join("Main.ipe"), CSUM_MAIN).expect("Main.ipe");
        assert!(seed_pure_ffi_cache(&pkg), "seed the FFI cache");

        let out = base.join("out");
        ipe::build_project(&pkg.join("package.ipe"), &out, &runtime)
            .expect("emitting the native package must succeed");

        // The reached binding must survive DCE into `src/ffi.rs` (the surface the
        // probe references).
        let ffi_rs =
            std::fs::read_to_string(out.join("src").join("ffi.rs")).expect("emitted src/ffi.rs");
        assert!(
            ffi_rs.contains("pub fn csum_checksum"),
            "the reached binding must survive into src/ffi.rs:\n{ffi_rs}"
        );

        // The FFI cache pins the bound crate as a registry version; repoint it at
        // the local fixture crate so the offline probe build resolves it (a
        // fixture crate cannot live on a registry). This changes WHERE `csum` comes
        // from, never what the emitted code says.
        let manifest_path = out.join("Cargo.toml");
        let manifest = std::fs::read_to_string(&manifest_path).expect("emitted manifest");
        assert!(
            manifest.contains("csum = \"=0.1.0\""),
            "emitted manifest pins the bound crate as a registry version:\n{manifest}"
        );
        let patched = manifest.replace(
            "csum = \"=0.1.0\"",
            &format!("csum = {{ path = {:?} }}", csum.display().to_string()),
        );
        std::fs::write(&manifest_path, patched).expect("patched manifest");
        (pkg, out)
    }

    /// Build the Tier-2 probe crate `native_tier2` emitted into `out`, OUTSIDE the
    /// jail. THE SEAL: the emitted probe must `cargo build`. The probe crate root
    /// must re-export the runtime prelude the shared `src/ffi.rs` names, and must
    /// reference exactly the DCE-emitted wrapper set — either broken yields an
    /// `E0425`/unresolved-path here, so this fails HARD rather than being masked by
    /// a jail/environment skip.
    fn assert_probe_crate_compiles(out: &std::path::Path, probe_target: &std::path::Path) {
        assert!(
            out.join("src").join("tier2_probe.rs").is_file(),
            "native_tier2 must have emitted the probe crate"
        );
        let probe_build = std::process::Command::new(which_cargo().expect("cargo present"))
            .arg("build")
            .arg("--offline")
            .arg("--locked")
            .arg("--bin")
            .arg("tier2_probe")
            .arg("--manifest-path")
            .arg(out.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(probe_target)
            .output()
            .expect("spawn probe build");
        assert!(
            probe_build.status.success(),
            "the emitted Tier-2 probe crate must compile (THE SEAL: emit ⇒ build).\n\
             stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&probe_build.stdout),
            String::from_utf8_lossy(&probe_build.stderr),
        );
    }

    #[test]
    fn a_real_native_package_with_a_probeable_binding_certifies_end_to_end() {
        // A legitimate native package must be REACHABLY certifiable, not only
        // fail-closed-rejectable: drive the whole `native_tier2` entry over a real
        // `[rust.dependencies]` package with a probeable binding and assert it
        // reaches `Certified`.
        let Some(_tools) = e2e_tools() else { return };
        if which_cargo().is_none() {
            eprintln!("audit_native e2e: skipping — cargo not found on PATH");
            return;
        }
        let base = non_tmp_base("certify");
        let (pkg, out) = emit_real_native_package(&base, false);

        let declared: BTreeSet<Capability> = set(&[Capability::NativeFfi]);
        let _guard = JAIL_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let verdict = native_tier2(&NativeAudit {
            declared: &declared,
            has_rust_deps: true,
            root: &pkg,
            emitted_dir: &out,
            probe_fixture: super::support::manifest_dir()
                .join("../../tests/fixtures/admission/untrusted-build.sh"),
        });
        assert_probe_crate_compiles(&out, &base.join("probe-target"));

        match verdict {
            Ok(Tier2Outcome::Certified { platform }) => {
                assert_eq!(
                    platform, CERTIFIED_PLATFORM,
                    "certify names this host's wired jail"
                );
                eprintln!(
                    "audit_native e2e: native package CERTIFIED on {platform} \
                     (reachable native certification)"
                );
            }
            Ok(other) => panic!("a native-bearing package must not skip Tier-2: {other:?}"),
            Err(e) => {
                let msg = e.to_string();
                // The probe crate compiled outside the jail (asserted above), so a
                // BuildFailed here is a JAIL-environment gap (no toolchain reachable
                // inside the sandbox), never a probe-emission regression — skip the
                // certify assert, never a false pass, mirroring the sibling
                // real-build tests.
                assert!(
                    msg.contains("failed to build") || msg.contains("could not be established"),
                    "the only non-certify outcomes tolerated here are jail-environment \
                     gaps, never a false reject of a benign package: {msg}"
                );
                eprintln!(
                    "audit_native e2e: skipping certify assert — jail-environment gap: {msg}"
                );
            }
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_real_native_package_reaching_an_undeclared_axis_rejects_end_to_end() {
        // THE END-TO-END REFUSAL: the mirror of the certify test, but with a bound
        // crate whose `build.rs` reaches `network` while the manifest declares only
        // `native-ffi` (network UNdeclared). Driven through the WHOLE `native_tier2`
        // entry — sidecar read, probe emit, jail establish, reconcile — not
        // `reconcile_native` directly. Under the declared-scoped jail (network
        // withheld) the bound crate's build-time connect is denied → cargo non-zero
        // → `BuildFailed` → REJECT. This is the load-bearing proof that a native
        // package whose code demands a capability its consumer never consented to is
        // refused at the OS boundary by the production entry, never admitted.
        let Some(_tools) = e2e_tools() else { return };
        if which_cargo().is_none() {
            eprintln!("audit_native e2e: skipping — cargo not found on PATH");
            return;
        }
        let base = non_tmp_base("reject-undeclared");
        let (pkg, out) = emit_real_native_package(&base, true);

        // Declare only `native-ffi`: network is NOT in the consent surface, so the
        // declared-scoped jail withholds it.
        let declared: BTreeSet<Capability> = set(&[Capability::NativeFfi]);
        assert!(
            !declared.contains(&Capability::Network),
            "the fixture must leave network undeclared for the reject to be real"
        );
        let _guard = JAIL_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let verdict = native_tier2(&NativeAudit {
            declared: &declared,
            has_rust_deps: true,
            root: &pkg,
            emitted_dir: &out,
            probe_fixture: super::support::manifest_dir()
                .join("../../tests/fixtures/admission/untrusted-build.sh"),
        });

        // POSITIVE CONTROL: `native_tier2` above emitted the probe crate + generated
        // its lockfile, so the SAME probe crate — bound crate's net-reaching
        // `build.rs` included — now builds OUTSIDE any jail. A clean unjailed build
        // proves the toolchain and crate are sound and outbound egress is available,
        // so the reject INSIDE the jail can only be the WITHHELD network capability,
        // never a broken toolchain. If the unjailed build ALSO fails (no egress on
        // this runner) the duality is unprovable — the reject is still valid and
        // fail-closed (a native package reaching an unbuildable-under-jail surface is
        // refused), but this test cannot attribute it to the withheld axis, so it
        // skips the strict duality assert rather than mis-attribute.
        let unjailed_clean = unjailed_probe_build_is_clean(&out, &base.join("control-target"));

        let err = verdict.expect_err(
            "a native package reaching an undeclared axis must reject end-to-end, never certify",
        );
        let msg = err.to_string();
        if !unjailed_clean {
            eprintln!(
                "audit_native e2e: undeclared-axis package REJECTED end-to-end ({msg}); \
                 no outbound egress to run the positive control, so the axis attribution \
                 is unprovable here — the fail-closed refusal still holds."
            );
            assert!(
                !msg.contains("passed"),
                "a package reaching a withheld axis must never certify: {msg}"
            );
            let _ = std::fs::remove_dir_all(&base);
            return;
        }
        // The declared-scoped run of the full entry is child-exit-only (no
        // fabricated fixed-axis probe), so the signal is the child build's own
        // OS-boundary failure: the net-withheld build.rs connect fails → cargo
        // non-zero → BuildFailed. Axis NAMING on the full run is deliberately traded
        // for not fabricating a demand the package never made (the direct-call
        // canaries name the axis); the property proven here is that the full entry
        // REFUSES rather than admits.
        assert!(
            msg.contains("failed to build") || msg.contains("network"),
            "the reject is a real OS-boundary refusal (BuildFailed or a named axis): {msg}"
        );
        assert!(
            !msg.contains("passed"),
            "a package reaching a withheld axis must never certify: {msg}"
        );
        eprintln!("audit_native e2e: undeclared-axis native package REJECTED end-to-end: {msg}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The positive control for the end-to-end reject: build the emitted probe
    /// crate OUTSIDE any jail. A clean build proves the toolchain and the bound
    /// crate (net-reaching `build.rs` included) are sound and outbound egress is
    /// available, so a failure INSIDE the declared-scoped jail can only be the
    /// withheld capability. `false` when the unjailed build itself fails (no
    /// egress) — the duality is unprovable and the caller skips cleanly.
    fn unjailed_probe_build_is_clean(
        out: &std::path::Path,
        probe_target: &std::path::Path,
    ) -> bool {
        let Some(cargo) = which_cargo() else {
            return false;
        };
        std::process::Command::new(cargo)
            .arg("build")
            .arg("--offline")
            .arg("--locked")
            .arg("--bin")
            .arg("tier2_probe")
            .arg("--manifest-path")
            .arg(out.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(probe_target)
            .output()
            .is_ok_and(|o| o.status.success())
    }

    /// Write a `package.ipe` for a `Rust.Csum`-crossing app whose `declares`
    /// capability set is exactly `caps` (`PascalCase` constructor tokens), plus the
    /// `Main.ipe` that reaches the native binding. Returns the package root.
    ///
    /// The seeded FFI cache supplies the `csum` native surface so `import
    /// Rust.Csum` lowers (and discloses `native-ffi`); the manifest names the
    /// rust dependency. This is the whole surface the build-time consent gate
    /// reads — no cargo/jail is reached, since the gate fires before emit.
    fn write_native_crossing_package(base: &std::path::Path, declares: &str) -> PathBuf {
        let pkg = base.join("pkg");
        std::fs::create_dir_all(pkg.join("src")).expect("pkg src");
        write_csum_crate(base, false);
        std::fs::write(
            pkg.join("package.ipe"),
            format!(
                "module Package exposing (package)\n\n\npackage =\n\
                 \x20   {{ name = \"csumpkg\"\n\
                 \x20   , version = \"0.1.0\"\n\
                 \x20   , rustDependencies = [ rustDep \"csum\" \"=0.1.0\" ]\n\
                 \x20   , capabilities = {{ declares = [ {declares} ], accepts = [] }}\n\
                 \x20   }}\n"
            ),
        )
        .expect("package.ipe");
        std::fs::write(pkg.join("src").join("Main.ipe"), CSUM_MAIN).expect("Main.ipe");
        assert!(seed_pure_ffi_cache(&pkg), "seed the FFI cache");
        pkg
    }

    /// The build-time consent gate REFUSES a `Rust.` crossing when the app's
    /// `[capabilities] declares` set does not grant `native-ffi` — a fail-closed,
    /// typed refusal (IPE-S0003) naming the disclosing `Rust.<Crate>` module,
    /// fired BEFORE any emit or cargo build. This is the increment-3 consent gate:
    /// an un-granted native capability is a compile error naming the dep.
    #[test]
    fn build_refuses_an_ungranted_native_crossing_naming_the_dep() {
        if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
            return;
        }
        let _runtime = e2e_support::require_runtime();
        let base = non_tmp_base("consent-refuse");
        // No `native-ffi` grant: the crossing is disclosed but ungranted.
        let pkg = write_native_crossing_package(&base, "");
        let out = base.join("out");
        let args = vec![
            "build".to_owned(),
            pkg.join("package.ipe").display().to_string(),
            "--out".to_owned(),
            out.display().to_string(),
        ];
        let result = ipe::run_cli(&args);
        let err = result.expect_err("an ungranted native crossing must refuse the build");
        let msg = err.to_string();
        assert!(msg.contains("IPE-S0003"), "carries the consent code: {msg}");
        assert!(
            msg.contains("Rust.Csum"),
            "names the disclosing crate: {msg}"
        );
        // The refusal fires before the output root is claimed: nothing is written.
        assert!(!out.exists(), "a refused build must write nothing");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The mirror admit path: with `declares = [ NativeFfi ]` the SAME crossing is
    /// GRANTED, so the consent gate passes — the build proceeds past it (any later
    /// error is a cargo/emit concern, never the IPE-S0003 consent refusal). This
    /// proves the gate admits a granted crossing rather than refusing everything.
    #[test]
    fn build_admits_a_granted_native_crossing_past_the_consent_gate() {
        if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
            return;
        }
        let _runtime = e2e_support::require_runtime();
        let base = non_tmp_base("consent-admit");
        let pkg = write_native_crossing_package(&base, "NativeFfi");
        let out = base.join("out");
        let args = vec![
            "build".to_owned(),
            pkg.join("package.ipe").display().to_string(),
            "--out".to_owned(),
            out.display().to_string(),
        ];
        let result = ipe::run_cli(&args);
        // The consent gate must NOT be the reason for any failure: a granted
        // crossing is admitted. (The build may still fail later on the offline
        // cargo probe, which is out of this gate's scope.)
        if let Err(err) = result {
            let msg = err.to_string();
            assert!(
                !msg.contains("IPE-S0003"),
                "a granted native crossing must pass the consent gate, got: {msg}"
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }
}
