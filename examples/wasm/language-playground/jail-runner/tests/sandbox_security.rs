//! The load-bearing security proofs for the playground `/run` path: the jail
//! HOLDS for user-derived code. Each test drives the SAME `run_jailed` helpers
//! the server uses and asserts the sandbox denies the forbidden effect (network
//! / out-of-jail read / fork) or kills a runaway, and that a benign program
//! returns its real stdout.
//!
//! Two program sources are exercised, both through the identical jailed build+run
//! path:
//!   * real Ipê programs emitted by the trusted `ipe` compiler (the benign-run
//!     and infinite-loop proofs), and
//!   * hand-authored adversarial Rust `main.rs` staged directly into an emitted
//!     crate (the network / filesystem / fork proofs). Adversarial Rust is the
//!     stronger probe: it actively attempts to escape, which a benign Ipê program
//!     cannot express, and it is exactly the shape a compromised emit could take.
//!
//! Heavy (emit + `cargo build` + run inside bubblewrap), so gated behind
//! `IPE_PLAYGROUND_E2E=1` — mirroring the compiler SEAL's `IPE_E2E`. Needs
//! `bwrap`, `timeout`, `prlimit`, a Rust toolchain, and the `ipe` binary
//! (`IPE_BIN`, else `<CARGO_TARGET_DIR>/debug/ipe`).

// Test code: `unwrap`/`expect`/`panic` on a failed setup step are the assertion,
// matching the crate's other `tests/*.rs` (allow-*-in-tests in clippy.toml only
// covers `#[test]` bodies, not the shared helper fns here).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

use ipe_sandbox::run_jail::netns_jail_available;
use playground_jail_runner::run_jailed::{
    self, PhaseOutcome, app_binary_path, jailed_build, jailed_run, probe_or_refuse,
    seed_cargo_home, seed_target_dir,
};

fn e2e_enabled() -> bool {
    ipe_env::var("IPE_PLAYGROUND_E2E").is_ok()
}

/// Returns the bwrap path when the netns jail can be established on this host,
/// prints a skip reason and returns `None` otherwise. The caller returns early on
/// `None` — tests that run under `--unshare-net` skip rather than hard-fail when
/// the host cannot configure loopback inside an unprivileged user namespace.
fn jail_or_skip(test: &str) -> Option<std::path::PathBuf> {
    // In E2E mode (the CI gate sets IPE_PLAYGROUND_E2E=1 after installing bwrap),
    // refuse to skip: a required jail proof that silently skips would pass green
    // having verified nothing. A missing jail primitive here is a hard failure,
    // not a skip. Locally, without the flag, skipping stays a dev convenience.
    let require = ipe_env::var("IPE_PLAYGROUND_E2E").is_ok();
    let Some(bwrap) = ipe_sandbox::probe().bwrap else {
        assert!(
            !require,
            "{test}: IPE_PLAYGROUND_E2E=1 but bwrap is absent — refusing to \
             skip a required jail proof (the sandbox was never exercised)"
        );
        eprintln!("{test}: SKIP — bwrap absent on this host");
        return None;
    };
    if !netns_jail_available(&bwrap) {
        assert!(
            !require,
            "{test}: IPE_PLAYGROUND_E2E=1 but the netns jail is unavailable — \
             refusing to skip a required jail proof (the sandbox was never exercised)"
        );
        eprintln!(
            "{test}: SKIP — netns jail unavailable on this host \
             (unprivileged userns cannot configure loopback)"
        );
        return None;
    }
    Some(bwrap)
}

/// Repo root: `examples/wasm/language-playground/jail-runner` →
/// `language-playground` → `wasm` → `examples` → repo.
fn repo_root() -> PathBuf {
    e2e_support::manifest_dir!()
        .ancestors()
        .nth(4)
        .expect("repo root")
        .to_path_buf()
}

fn ipe_bin() -> PathBuf {
    if let Ok(p) = ipe_env::var("IPE_BIN") {
        return PathBuf::from(p);
    }
    let target = ipe_env::var_os("CARGO_TARGET_DIR")
        .map_or_else(|| repo_root().join("target"), PathBuf::from);
    target.join("debug").join("ipe")
}

fn runtime_dir() -> PathBuf {
    repo_root().join("src/runtime/rust/src")
}

/// A staged crate ready for the jailed build+run, holding its scratch dir alive.
///
/// `scoped_tmp` is the CRATE ROOT (where `Cargo.toml` sits): the jail-runner's
/// `jailed_build` expects the manifest at `<scoped_tmp>/Cargo.toml`, exactly as
/// the server stages client projects.
struct Staged {
    /// Held alive for the duration of the test: dropping it deletes the scratch
    /// tree (including the jailed build artifacts inside `crate_dir`).
    #[allow(dead_code)]
    scratch: tempfile::TempDir,
    crate_dir: PathBuf,
}

impl Staged {
    fn scoped_tmp(&self) -> &Path {
        &self.crate_dir
    }
}

/// Emit a native crate from Ipê `source` with the trusted compiler, then
/// pre-warm + seed the offline dependency cache — leaving a crate ready to build
/// offline in the jail.
fn stage_ipe(source: &str) -> Staged {
    let scratch = tempfile::TempDir::new_in(ipe_test_temp::temp_root()).expect("scratch");
    // `--out` names the output root, kept apart from the source; the emitted
    // crate is its `rust/` area.
    let out_root = scratch.path().join("out");
    let crate_dir = out_root.join("rust");
    let src_dir = scratch.path().join("src-ipe");
    let entry = src_dir.join("Main.ipe");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(&entry, source).unwrap();

    let emit = Command::new(ipe_bin())
        .arg("dev")
        .arg("build")
        .arg(&entry)
        .arg("--out")
        .arg(&out_root)
        .arg("--runtime")
        .arg(runtime_dir())
        .env("CARGO_TERM_PROGRESS_WHEN", "never")
        .output()
        .expect("spawn ipe dev build");
    assert!(
        emit.status.success(),
        "ipe dev build (emit) failed:\n{}",
        String::from_utf8_lossy(&emit.stderr)
    );

    warm_and_seed(&crate_dir);
    Staged { scratch, crate_dir }
}

/// Stage an adversarial crate: an emitted native crate whose `src/main.rs` is
/// replaced with hand-authored Rust that tries to escape the jail. The manifest
/// and vendored runtime come from a real `ipe` emit so the crate is identical in
/// shape to a user program — only the `main.rs` differs.
fn stage_adversarial_rust(main_rs: &str) -> Staged {
    // Emit a trivial program to get the canonical crate scaffold, then overwrite
    // its main.rs with the probe. This keeps the manifest + vendored runtime +
    // dependency set byte-identical to a real user build.
    let staged = stage_scaffold_only();
    let main = staged.scoped_tmp().join("src").join("main.rs");
    std::fs::write(&main, main_rs).expect("overwrite main.rs");
    staged
}

/// The canonical crate scaffold (manifest + vendored runtime) from a trivial
/// emit, warmed and seeded — but the caller replaces `main.rs`.
fn stage_scaffold_only() -> Staged {
    let scratch = tempfile::TempDir::new_in(ipe_test_temp::temp_root()).expect("scratch");
    // `--out` names the output root, kept apart from the source; the emitted
    // crate is its `rust/` area.
    let out_root = scratch.path().join("out");
    let crate_dir = out_root.join("rust");
    let src_dir = scratch.path().join("src-ipe");
    let entry = src_dir.join("Main.ipe");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(
        &entry,
        "module Main exposing (main)\n\nimport Ipe.Io as Io\n\nmain =\n    Io.println \"scaffold\"\n",
    )
    .unwrap();
    let emit = Command::new(ipe_bin())
        .arg("dev")
        .arg("build")
        .arg(&entry)
        .arg("--out")
        .arg(&out_root)
        .arg("--runtime")
        .arg(runtime_dir())
        .env("CARGO_TERM_PROGRESS_WHEN", "never")
        .output()
        .expect("spawn ipe dev build");
    assert!(
        emit.status.success(),
        "scaffold emit failed:\n{}",
        String::from_utf8_lossy(&emit.stderr)
    );
    warm_and_seed(&crate_dir);
    Staged { scratch, crate_dir }
}

/// Pre-warm the crate's fixed dependency closure by `cargo build`ing it once into
/// a warm `CARGO_HOME` + target (only our trusted deps run build scripts here),
/// then seed BOTH into the jail-visible scratch — mirroring the server, so the
/// jailed build is fully offline and compiles only the user crate.
///
/// A repo-level warm target (`IPE_PLAYGROUND_WARM_TARGET`, else a shared cache
/// dir) is reused across tests so only the FIRST test pays the closure build.
fn warm_and_seed(crate_dir: &Path) {
    let warm_home = warm_root().join("cargo-home");
    let warm_target = warm_root().join("target");
    std::fs::create_dir_all(&warm_home).unwrap();
    std::fs::create_dir_all(&warm_target).unwrap();
    let build = Command::new("cargo")
        .arg("build")
        .arg("--manifest-path")
        .arg(crate_dir.join("Cargo.toml"))
        .arg("--target-dir")
        .arg(&warm_target)
        .env("CARGO_HOME", &warm_home)
        .env("CARGO_TERM_PROGRESS_WHEN", "never")
        .output()
        .expect("spawn cargo build");
    assert!(
        build.status.success(),
        "warm cargo build failed:\n{}",
        String::from_utf8_lossy(&build.stderr)
    );
    seed_cargo_home(crate_dir, &warm_home).expect("seed cargo home");
    seed_target_dir(crate_dir, &warm_target).expect("seed target dir");
}

/// A shared warm-cache root reused across tests (so the dependency closure builds
/// once). Under the sanctioned cache root by default.
fn warm_root() -> PathBuf {
    ipe_env::var_os("IPE_PLAYGROUND_WARM_TARGET").map_or_else(
        || ipe_test_temp::temp_root().join("ipe-playground-test-warm"),
        PathBuf::from,
    )
}

/// Build (jailed) then run (jailed) a staged crate. Returns the build outcome and
/// the run outcome (`None` if the build failed).
fn build_and_run(staged: &Staged) -> (PhaseOutcome, Option<PhaseOutcome>) {
    let caps = probe_or_refuse().expect("jail primitives present");
    let scoped_tmp = staged.scoped_tmp();
    let build = jailed_build(&caps, scoped_tmp).expect("jailed build spawns");
    if build.status != Some(0) {
        return (build, None);
    }
    let app = app_binary_path(scoped_tmp);
    assert!(app.is_file(), "no ipe-app after a clean build");
    let run = jailed_run(&caps, scoped_tmp, &app).expect("jailed run spawns");
    (build, Some(run))
}

// ── (e) A benign program prints and exits 0 ───────────────────────────────────

#[test]
fn hello_world_runs_and_returns_stdout() {
    if !e2e_enabled() {
        return;
    }
    if jail_or_skip("hello_world_runs_and_returns_stdout").is_none() {
        return;
    }
    let staged = stage_ipe(
        "module Main exposing (main)\n\nimport Ipe.Io as Io\n\nmain =\n    Io.println \"hello\"\n",
    );
    let (build, run) = build_and_run(&staged);
    assert_eq!(build.status, Some(0), "build stderr:\n{}", build.stderr);
    let run = run.expect("ran");
    assert_eq!(run.status, Some(0), "run stderr:\n{}", run.stderr);
    assert!(
        run.stdout.contains("hello"),
        "expected `hello` in stdout, got: <{}> stderr <{}>",
        run.stdout,
        run.stderr
    );
}

// ── (a) Network is denied ─────────────────────────────────────────────────────

#[test]
fn network_access_is_denied() {
    if !e2e_enabled() {
        return;
    }
    if jail_or_skip("network_access_is_denied").is_none() {
        return;
    }
    // A TCP connect to a routable address. Under the jail's fresh empty net
    // namespace (`--unshare-net`) there is NO route, so `connect` fails. The probe
    // prints DENIED on failure and CONNECTED on success; the jail must yield
    // DENIED (or a kill), never CONNECTED.
    let probe = r#"
use std::net::TcpStream;
use std::time::Duration;
fn main() {
    match TcpStream::connect_timeout(
        &"1.1.1.1:80".parse().unwrap(),
        Duration::from_secs(2),
    ) {
        Ok(_) => println!("CONNECTED"),
        Err(e) => println!("DENIED: {e}"),
    }
}
"#;
    let staged = stage_adversarial_rust(probe);
    let (build, run) = build_and_run(&staged);
    assert_eq!(
        build.status,
        Some(0),
        "probe build stderr:\n{}",
        build.stderr
    );
    let run = run.expect("ran");
    assert!(
        !run.stdout.contains("CONNECTED"),
        "NETWORK WAS NOT DENIED — probe connected:\n{}",
        run.stdout
    );
    assert!(
        run.stdout.contains("DENIED") || run.killed,
        "expected DENIED or a kill, got status={:?} stdout <{}>",
        run.status,
        run.stdout
    );
}

// ── (b) Reading outside the scratch jail is denied ────────────────────────────

#[test]
fn out_of_jail_filesystem_read_is_denied() {
    if !e2e_enabled() {
        return;
    }
    if jail_or_skip("out_of_jail_filesystem_read_is_denied").is_none() {
        return;
    }
    // Target a repo file that must never be visible inside the jail. The jail's
    // `/home` and `/root` are tmpfs masks and the only writable/visible mount is
    // the scratch bind, so a path under the developer's checkout cannot be read.
    let secret = repo_root().join("PRINCIPLES.md");
    let probe = format!(
        r#"
use std::fs;
fn main() {{
    match fs::read_to_string("{}") {{
        Ok(s) => println!("LEAKED {{}} bytes: {{}}", s.len(), &s[..s.len().min(40)]),
        Err(e) => println!("DENIED: {{e}}"),
    }}
}}
"#,
        secret.display()
    );
    let staged = stage_adversarial_rust(&probe);
    let (build, run) = build_and_run(&staged);
    assert_eq!(
        build.status,
        Some(0),
        "probe build stderr:\n{}",
        build.stderr
    );
    let run = run.expect("ran");
    assert!(
        !run.stdout.contains("LEAKED"),
        "OUT-OF-JAIL FILE WAS READ:\n{}",
        run.stdout
    );
    assert!(
        run.stdout.contains("DENIED") || run.killed,
        "expected DENIED, got status={:?} stdout <{}>",
        run.status,
        run.stdout
    );
}

// ── (c) A spawned subprocess is CONFINED to the same jail ─────────────────────

#[test]
fn a_spawned_subprocess_cannot_escape_the_jail() {
    if !e2e_enabled() {
        return;
    }
    if jail_or_skip("a_spawned_subprocess_cannot_escape_the_jail").is_none() {
        return;
    }
    // The honest guarantee (see docs/topics/playground.md threat model): the run jail's
    // seccomp filter denies the legacy `fork`/`vfork`/`clone` subprocess paths but
    // NOT `clone3` — which `posix_spawn` uses on modern glibc — because the tokio
    // runtime creates its threads via `clone3` and seccomp cannot inspect its
    // pointer-borne flags. So a subprocess CAN start, but it inherits the SAME
    // bubblewrap namespace: it is net-denied, filesystem-jailed to the scratch
    // bind, and bounded by the same `prlimit` caps — it gains NO capability the
    // parent lacked. This probe spawns a child that tries to read a host file
    // OUTSIDE the jail; the child must be denied exactly as the parent would be.
    let secret = repo_root().join("PRINCIPLES.md");
    let probe = format!(
        r#"
use std::process::Command;
fn main() {{
    let out = Command::new("/bin/cat").arg("{}").output();
    match out {{
        Ok(o) => {{
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("six technical principles") {{
                println!("CHILD-LEAKED");
            }} else {{
                println!("CHILD-CONFINED (exit {{:?}}, {{}} out bytes)", o.status.code(), s.len());
            }}
        }}
        Err(e) => println!("CHILD-DENIED-SPAWN: {{e}}"),
    }}
}}
"#,
        secret.display()
    );
    let staged = stage_adversarial_rust(&probe);
    let (build, run) = build_and_run(&staged);
    assert_eq!(
        build.status,
        Some(0),
        "probe build stderr:\n{}",
        build.stderr
    );
    let run = run.expect("ran");
    // The load-bearing property: even if a child process starts, it CANNOT read a
    // host file outside the jail. The repo file is unreadable from the child.
    assert!(
        !run.stdout.contains("CHILD-LEAKED"),
        "a SPAWNED CHILD ESCAPED the jail and read a host file:\n{}",
        run.stdout
    );
}

// ── (c2) A fork bomb is bounded by the process cap, not left to run ────────────

#[test]
fn a_fork_bomb_is_bounded_not_unbounded() {
    if !e2e_enabled() {
        return;
    }
    if jail_or_skip("a_fork_bomb_is_bounded_not_unbounded").is_none() {
        return;
    }
    // Spawn children in a tight loop. `prlimit --nproc` caps the process/thread
    // count and `--unshare-pid` + the wall clock bound the blast radius: the run
    // returns (killed or self-limited) rather than exhausting the host's PIDs and
    // hanging the server. Reaching the assertion at all proves the server kept
    // control — `jailed_run` returned.
    let probe = r#"
use std::process::Command;
fn main() {
    let mut spawned = 0u64;
    for _ in 0..100000 {
        if Command::new("/bin/true").spawn().is_ok() {
            spawned += 1;
        } else {
            break;
        }
    }
    println!("spawned {spawned}");
}
"#;
    let staged = stage_adversarial_rust(probe);
    let (build, run) = build_and_run(&staged);
    assert_eq!(
        build.status,
        Some(0),
        "probe build stderr:\n{}",
        build.stderr
    );
    // The property: the server regained control. A `None`/kill or a bounded exit
    // both satisfy it; an unbounded hang would have tripped the outer test
    // `timeout` instead of returning here.
    let _ = run.expect("jailed_run returned rather than hanging the server");
}

// ── (d) An infinite loop is killed by the wall-clock limit ────────────────────

#[test]
fn infinite_loop_is_killed_by_the_time_limit() {
    if !e2e_enabled() {
        return;
    }
    if jail_or_skip("infinite_loop_is_killed_by_the_time_limit").is_none() {
        return;
    }
    // Non-terminating Rust. The run phase's `timeout --kill-after=5s <wall>`
    // SIGKILLs it; `jailed_run` returns `killed` (status None) rather than hanging
    // the server. Uses the adversarial-Rust path so the loop is unambiguous.
    let probe = r"
fn main() {
    let mut x: u64 = 0;
    loop {
        x = x.wrapping_add(1);
        std::hint::black_box(x);
    }
}
";
    let staged = stage_adversarial_rust(probe);
    let (build, run) = build_and_run(&staged);
    assert_eq!(
        build.status,
        Some(0),
        "probe build stderr:\n{}",
        build.stderr
    );
    let run = run.expect("ran");
    assert!(
        run.killed,
        "an infinite loop was NOT killed by the wall clock: status={:?}",
        run.status
    );
}

// ── Fail-closed contract (runs without e2e) ───────────────────────────────────

#[test]
fn probe_refusal_names_the_sandbox() {
    // A pure API-contract check: any refusal must name the sandbox so the endpoint
    // can surface a clear fail-closed message. (On a host WITH the primitives the
    // probe returns Ok, which is also acceptable — the refusal shape is
    // unit-tested in the crate.)
    let _ = run_jailed::RunCaps::run_defaults();
    if let Err(refusal) = probe_or_refuse() {
        assert!(
            refusal.reason.contains("sandbox refused"),
            "refusal must name the sandbox: {}",
            refusal.reason
        );
    }
}
