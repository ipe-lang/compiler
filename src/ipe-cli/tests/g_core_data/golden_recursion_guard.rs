//! Recursion-guard end-to-end regressions — the `DoS` containment proof.
//!
//! `recursion_limit_trip` is an unbounded non-tail mutual recursion with no
//! reachable base case. On the normalized 8 MiB stack:
//!
//!   * WITHOUT the guard the native stack overflows and the process is killed by
//!     signal — SIGABRT, `exit_code == None`, no classified line — an uncatchable
//!     abort that bypasses every panic-containment mechanism.
//!   * WITH the guard the depth budget trips first: the `panic!` unwinds into the
//!     panic classifier, so the process exits with a CODE (`Some`, never
//!     signal-killed) and stderr carries the classified `RecursionLimit` line.
//!     The server/CLI survives the runaway recursion.
//!
//! `recursion_normal_depth` is a correct, bounded, non-tail recursion ~1000 deep:
//! it returns the right value with a clean exit, proving the guard never
//! false-trips on legitimate deep recursion.
//!
//! Gated on `IPE_E2E=1`; without it each test returns early. Run:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_recursion_guard
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

/// Compile `tests/golden/<name>/Main.ipe` into an emitted Rust project and return
/// its directory. Fails the test loudly on a compile error.
fn compile_golden(name: &str) -> PathBuf {
    let root = repo_root();
    let entry = golden_dir(&root, name).join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());
    out
}

/// The `DoS` containment proof. An unbounded non-tail recursion on the normalized
/// 8 MiB stack trips the depth budget and unwinds into the classifier: the
/// process exits with a CODE (not signal-killed) and stderr carries the
/// classified `RecursionLimit` line. An unguarded build would exhaust the native
/// stack and SIGABRT here (`exit_code == None`, no classified line).
#[test]
fn recursion_limit_trip_survives_as_classified_exit_not_abort() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let dir = compile_golden("recursion_limit_trip");
    let out = crate::support::build_and_run_emitted_capturing_stderr("recursion_limit_trip", &dir);

    // Survives: killed-by-signal presents as `exit_code == None`; a guarded trip
    // exits with a code. This is the load-bearing distinction — the process must
    // NOT abort. On the synchronous CLI path the guard's `panic!` unwinds through
    // `main` after the classifier logs, so the process exits with Rust's panic
    // code (a nonzero `Some`), never a signal death.
    assert!(
        out.exit_code.is_some(),
        "the runaway recursion must exit with a CODE (a guarded, catchable trip), \
         never be killed by signal (an unguarded stack-overflow abort); got \
         exit_code None\n--- stderr ---\n{}",
        out.stderr
    );
    assert_ne!(
        out.exit_code,
        Some(0),
        "a tripped recursion is a runtime defect — it must exit nonzero\n--- stderr ---\n{}",
        out.stderr
    );

    // The classified line reaches the server-side log (stderr), naming the kind
    // and carrying the fixed message.
    assert!(
        out.stderr.contains("RecursionLimit"),
        "stderr must carry the classified RecursionLimit kind\n--- stderr ---\n{}",
        out.stderr
    );
    assert!(
        out.stderr.contains("maximum recursion depth exceeded"),
        "stderr must carry the fixed trip message\n--- stderr ---\n{}",
        out.stderr
    );
}

/// Non-regression: a correct bounded non-tail recursion ~1000 deep runs to a
/// clean exit and prints the right value — the guard never false-trips on
/// legitimate deep recursion.
#[test]
fn recursion_normal_depth_runs_clean_and_returns_value() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let dir = compile_golden("recursion_normal_depth");
    let out = crate::support::build_and_run_emitted("recursion_normal_depth", &dir);
    assert_eq!(
        out.exit_code,
        Some(0),
        "bounded recursion must exit cleanly; got {:?}",
        out.exit_code
    );
    assert_eq!(out.stdout.trim(), "500500");
}
