//! Cons / list PATTERN parity gate — the pattern engine's list shapes.
//!
//! The `List` type, its `[]` / `[a, b, c]` literals, and the
//! `::` cons OPERATOR live in value position. This gate covers the matching half: the
//! list shapes in PATTERN position — `[]`, `x :: xs`, `[a, b]`, and the
//! right-nested `a :: b :: rest` — across the parser, canonicaliser, type
//! constraints, Maranget exhaustiveness, and the Rust backend.
//!
//! Two programs exercise the surface:
//!
//! * `cons_sum` (positive) — `sum xs = case xs of [] -> 0 ; x :: rest ->
//!   x + sum rest` over `[1, 2, 3]`, printing `6`. The `case` lowers to a native
//!   Rust slice match over the runtime's `Vec<T>` list repr (`match (xs).as_slice()
//!   { [] => …, [x, rest @ ..] => … }`); the head element is rebound owned via
//!   `.clone()` and the tail via `.to_vec()`, so the arm body sees the Ipê `Int`
//!   / `List Int` types. Its emitted `main.rs` must be byte-identical to the
//!   checked-in golden, and (behind `IPE_E2E=1`) the emitted project must build
//!   and print the expected reference produces — captured in `expected_go.txt`
//!   / `oracle.meta` via the cached-oracle infra (no live in this gate).
//!
//! * `gate_list_nonexhaustive` (negative) — `case xs of x :: rest -> x`
//!   omits the `[]` arm. `List` is the closed `Nil | Cons` type, so the missing
//!   empty-list case is non-exhaustive: the usefulness check reports IPE-T0010
//!   (the soundness floor — a non-exhaustive list `case` MUST be caught before
//!   emit, never deferred to a rustc `E0004`). A gate golden has no program
//!   output, so it carries no `oracle.meta`.

use std::path::{Path, PathBuf};

use ipe::CliError;

use crate::support::repo_root;

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

/// Compile `tests/golden/<name>/Main.ipe` and assert the emitted `src/main.rs`
/// equals the checked-in `tests/golden/<name>/main.rs` byte-for-byte.
fn assert_byte_identical(name: &str) {
    let root = repo_root();
    let dir = golden_dir(&root, name);
    let entry = dir.join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_emit"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve: {:?}", runtime.err());
    let Ok(runtime) = runtime else { return };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());

    // Directory-diff the emitted project against the golden dir (byte-compares
    // the emitted `src/main.rs` against the golden `main.rs`). `dir` IS the golden
    // dir (`golden` was `dir.join("main.rs")`, so `golden.parent()` was provably
    // `dir`) — pass it directly, no fallible `.parent().expect(...)` re-derivation
    // (clippy::expect_used under the `-p ipe --tests -D warnings` gate).
    crate::support::assert_emitted_project_matches_golden_dir(&out, &dir);
}

/// Full spine: compile, build the emitted Cargo project, run it, and assert its
/// stdout matches the golden's CACHED golden oracle via the staleness-gated
/// `crate::support::assert_go_parity` — NO live oracle run. Gated on `IPE_E2E=1`.
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
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

/// Compile `tests/golden/<fixture>/Main.ipe` and assert it is rejected with the
/// expected diagnostic code (a gate golden — no program output).
fn assert_gate(fixture: &str, expected: ipe_diagnostics::Code) {
    let root = repo_root();
    let entry = golden_dir(&root, fixture).join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{fixture}_gate_emit"));
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(expected),
        "fixture {fixture}: expected {expected:?}, got build result {built:?}"
    );
}

#[test]
fn cons_sum_emits_byte_identical_main_rs() {
    assert_byte_identical("cons_sum");
}

#[test]
fn cons_sum_builds_and_prints_six() {
    assert_runs_and_matches_oracle("cons_sum");
}

#[test]
fn non_exhaustive_list_case_is_ipe_t0010() {
    assert_gate("gate_list_nonexhaustive", ipe_diagnostics::IPE_T0010);
}
