//! `Ipe.Error` module qualifier — minimal `Error = String` slice.
//!
//! Gated on `IPE_E2E=1`; without it the test returns early so the default
//! `cargo test` stays fast.
//!
//! ## Golden catalogue
//!
//! * `error_module` — `Task.onError (\e -> Io.println (Error.toString e))
//!   (Task.fail (Error.unexpected "boom"))`. Exercises the whole minimal Error
//!   surface end-to-end: `Error.unexpected` (message constructor, `String ->
//!   Error`), `Task.fail` on an `Error`-channel value, `Task.onError` with an
//!   `e : Error` handler parameter, and `Error.toString : Error -> String`.
//!   `Error.toString` renders the `ErrorKind` ADT as `"<Kind>: <message>"`, so an
//!   `Unexpected`-kind error carrying `"boom"` prints `Unexpected: boom`.
//!
//! Run:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_m86_error
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

/// Compile `tests/golden/<name>/Main.ipe`, build the emitted Cargo project,
/// run it, and assert its stdout matches the cached oracle. Gated on `IPE_E2E=1`.
fn assert_runs_and_matches_oracle(name: &str) {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let dir = golden_dir(&root, name);
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted(name, &out);
    crate::support::assert_go_parity(name, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "exit 0, matching the oracle");
}

/// The full minimal-Error round-trip: construct → fail → recover → render.
#[test]
fn error_module_round_trip() {
    assert_runs_and_matches_oracle("error_module");
}
