//! Task / Io / Time / System / Random / File parity gate — effect sequencing,
//! Task combinators, and the error channel.
//!
//! All tests are gated on `IPE_E2E=1`; without it they return early so the
//! default `cargo test` stays fast.
//!
//! ## Golden catalogue
//!
//! * `effect_sequencing` — `let _ = Io.println "step 1" in Io.println "step 2"`.
//!   The F1 auto-force rule (`let _ = Task in rest`) must sequence both effects;
//!   both lines appear in order on stdout.
//!
//! * `task_combinators` — `Task.andThen (\n -> println …) (Task.succeed 42)`.
//!   `Task.succeed` lifts a pure value; `Task.andThen` chains the effectful
//!   continuation.  Expected output: `42`.
//!
//! * `error_channel` — `Task.onError (\e -> Io.println "recovered") (Task.fail
//!   (Error.unexpected "an error"))`. `Task.fail` creates a failed task;
//!   `Task.onError` recovers it. `Task.fail` is pinned to `Error -> Task Error
//!   a` (class-7 fix), so the argument is an `Error`, not a bare `String`.
//!   Expected output: `recovered`.
//!
//! * `task_signed_helper` — `greet : String -> Task Error ()` signed top-level
//!   helper called from `main`.  Guards the `normalize_annotation_ty` fix that
//!   reconciles the canonical 2-arg annotation with the kernel's unary `Task a`.
//!   Expected output: `Hello, World!`.
//!
//! * `task_map_error_lambda` — `Task.onError (\e -> Io.println "recovered") …`.
//!   The lambda's `e` parameter must be inferred as `Error` (not a free variable)
//!   so the handler compiles without IPE-L0102.  Expected output: `recovered`.
//!
//! Run:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_m5a_task
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
/// run it, and assert its stdout matches the cached oracle.  Gated on
/// `IPE_E2E=1`.
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

// ── Effect sequencing ────────────────────────────────────────────────────────

/// `let _ = Io.println "step 1" in Io.println "step 2"` must sequence both effects
/// via the F1 auto-force rule, producing `step 1\nstep 2\n` on stdout.
#[test]
fn effect_sequencing() {
    assert_runs_and_matches_oracle("effect_sequencing");
}

// ── Task combinators ─────────────────────────────────────────────────────────

/// `Task.andThen (\n -> Io.println (String.fromInt n)) (Task.succeed 42)` must
/// lift the pure value 42 into a Task and chain the effectful continuation,
/// printing `42` on stdout.
#[test]
fn task_combinators() {
    assert_runs_and_matches_oracle("task_combinators");
}

// ── Error channel ────────────────────────────────────────────────────────────

/// `Task.onError (\e -> Io.println "recovered") (Task.fail (Error.unexpected "an
/// error"))` must create a failed task and recover via `onError`, printing
/// `recovered` on stdout.
#[test]
fn error_channel() {
    assert_runs_and_matches_oracle("error_channel");
}

// ── Task Error () signed helper ───────────────────────────────────────────────

/// `greet : String -> Task Error ()` is a signed top-level effectful helper.
/// The kernel builds a unary `Task a` while `from_canon` converts the
/// annotation to a binary `Task Error a`; without reconciliation this is a
/// IPE-T0001 "expected Task Error (), found Task ()". `normalize_annotation_ty`
/// reduces 2-arg `Task Error a` → 1-arg `Task a` at all annotation sites.
/// Expected output: `Hello, World!`.
#[test]
fn task_signed_helper() {
    assert_runs_and_matches_oracle("task_signed_helper");
}

// ── onError / mapError lambda ─────────────────────────────────────────────────

/// `Task.onError (\e -> Io.println "recovered") (Task.fail (Error.unexpected "an
/// error"))` exercises the `mapError`/`onError` `kernel_ty` fix: the handler
/// parameter `e` must be inferred as `Error` (not a free `var(1)`) so the
/// unused-lambda-param path doesn't trigger IPE-L0102 ("polymorphic
/// parameter"). `Task.fail` is pinned to `Error -> Task Error a`, hence the
/// `Error.unexpected` wrap rather than a bare string literal.
/// Expected output: `recovered`.
#[test]
fn task_map_error_lambda() {
    assert_runs_and_matches_oracle("task_map_error_lambda");
}
